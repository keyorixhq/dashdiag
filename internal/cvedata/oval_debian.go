//go:build linux

package cvedata

import (
	"compress/bzip2"
	"context"
	"encoding/xml"
	"fmt"
	"io"
	"os"
	"os/exec"
	"regexp"
	"strings"

	"github.com/keyorixhq/dashdiag/internal/platform"
)

// resolveDpkgQuery resolves "dpkg-query" to an absolute path via
// platform.ResolveTrustedTool (trusted system dirs, never the process's
// inherited $PATH — see internal/platform/trustedexec.go) before
// QueryInstalledDPKG execs it, so a directory prepended ahead of the real
// /usr/bin can't shadow dpkg-query for a privileged dsd invocation. A var
// (not a direct call) so tests can point QueryInstalledDPKG at a fake binary
// without needing it to live in one of those trusted directories.
var resolveDpkgQuery = platform.ResolveTrustedTool

// ubuntuPriorityToCVSS maps Ubuntu/Debian priority strings to approximate
// CVSS3 scores for bucketing. Ubuntu does not publish numeric CVSS scores
// in OVAL — only qualitative priorities.
var ubuntuPriorityToCVSS = map[string]float64{
	"critical":   9.5,
	"high":       8.0,
	"medium":     5.0,
	"low":        2.0,
	"negligible": 0.5,
}

// pkgInDistroRe matches criterion comments of the form:
// "PACKAGE package in noble is affected and may need fixing."
var pkgInDistroRe = regexp.MustCompile(`^(\S+) package in \S+ (?:is affected|needs fixing|may need fixing)`)

// dpkgEarlierRe matches criterion comments of the form:
// "openssl DPKG is earlier than 3.0.13-0ubuntu3.4"
// capturing (packageName, fixedVersion). This form only appears when a fix
// has been published for this release; "may need fixing" appears when it has not.
var dpkgEarlierRe = regexp.MustCompile(`^(\S+) DPKG is earlier than (\S+)$`)

// ubuntuPkgFix pairs a package name with the first version that fixes the CVE.
// fixedIn is empty when the criterion uses the "is affected and may need fixing"
// form — no fix has been published for this series yet.
type ubuntuPkgFix struct {
	name    string
	fixedIn string
}

// ubuntuVulnEntry is the version-aware internal representation of one
// Ubuntu/Debian OVAL vulnerability definition.
type ubuntuVulnEntry struct {
	cveID    string
	cvss     float64
	severity string
	pkgs     []ubuntuPkgFix
}

// parseUbuntuOVALVersionAware decodes Ubuntu/Debian OVAL XML and returns one
// ubuntuVulnEntry per CVE definition. For each affected package it captures:
//   - the fixedIn version from "X DPKG is earlier than VERSION" comments, or
//   - an empty fixedIn from "X package in Y is affected…" comments (no fix yet).
//
// The two comment forms are mutually exclusive within a definition for the same
// package: one appears when a fix is published, the other when it is not.
// Preference order: if a version-bearing comment is seen for a package, a later
// no-version comment for the same package does not downgrade it.
func parseUbuntuOVALVersionAware(r io.Reader) ([]ubuntuVulnEntry, error) {
	var defs ubuntuOVALDefs
	if err := xml.NewDecoder(r).Decode(&defs); err != nil {
		return nil, fmt.Errorf("parsing OVAL XML: %w", err)
	}
	// A real Ubuntu/Debian OVAL feed always contains definitions. Zero means
	// the download was truncated, a CDN/object-storage error body was served
	// instead of the real feed, or the input isn't OVAL at all — fail loudly
	// rather than let the scan silently come back "no vulnerable packages
	// found". Mirrors loadOVAL's guard for the SUSE/RHEL path (oval.go).
	if len(defs.Definitions) == 0 {
		return nil, fmt.Errorf("OVAL feed parsed 0 definitions — truncated, corrupt, or not an OVAL feed")
	}

	var entries []ubuntuVulnEntry
	for _, def := range defs.Definitions {
		if def.Class != "vulnerability" {
			continue
		}

		var cveID string
		for _, ref := range def.Metadata.References {
			if strings.EqualFold(ref.Source, "CVE") && strings.HasPrefix(ref.RefID, "CVE-") {
				cveID = strings.ToUpper(ref.RefID)
				break
			}
		}
		if cveID == "" {
			continue
		}

		priority := strings.ToLower(strings.TrimSpace(def.Metadata.Advisory.Severity))
		for _, c := range def.Metadata.Advisory.CVEs {
			if c.Priority != "" {
				priority = strings.ToLower(c.Priority)
				break
			}
		}
		cvss := ubuntuPriorityToCVSS[priority]
		severity := priority
		if priority != "" {
			severity = strings.ToUpper(priority[:1]) + strings.ToLower(priority[1:])
		}

		// pkgMap accumulates per-package information. A version-specific entry
		// (fixedIn != "") is never overwritten by a no-version entry for the
		// same package; the version-specific form is more informative.
		pkgMap := map[string]*ubuntuPkgFix{}
		addComment := func(comment string) {
			if m := dpkgEarlierRe.FindStringSubmatch(comment); m != nil {
				name := m[1]
				if existing, ok := pkgMap[name]; ok && existing.fixedIn != "" {
					return // already have a version for this package
				}
				pkgMap[name] = &ubuntuPkgFix{name: name, fixedIn: m[2]}
				return
			}
			if m := pkgInDistroRe.FindStringSubmatch(comment); m != nil {
				name := m[1]
				if _, ok := pkgMap[name]; !ok {
					pkgMap[name] = &ubuntuPkgFix{name: name}
				}
			}
		}
		for _, c := range def.Criteria.Criterions {
			addComment(c.Comment)
		}
		for _, cr := range def.Criteria.Criteria {
			for _, c := range cr.Criterions {
				addComment(c.Comment)
			}
		}

		if len(pkgMap) == 0 {
			continue
		}

		entries = append(entries, ubuntuVulnEntry{
			cveID:    cveID,
			cvss:     cvss,
			severity: severity,
			pkgs:     orderedUbuntuPkgs(def.Criteria, pkgMap),
		})
	}
	return entries, nil
}

// orderedUbuntuPkgs builds a deterministically-ordered slice of ubuntuPkgFix
// from the pkgMap, iterating the criteria in document order to preserve the
// original criterion sequence. A name that appears in both a version-bearing
// and a no-version criterion uses the already-resolved pkgMap entry.
func orderedUbuntuPkgs(crit ubuntuOVALCritTop, pkgMap map[string]*ubuntuPkgFix) []ubuntuPkgFix {
	seen := map[string]bool{}
	var pkgs []ubuntuPkgFix
	add := func(comment string) {
		var name string
		if m := dpkgEarlierRe.FindStringSubmatch(comment); m != nil {
			name = m[1]
		} else if m := pkgInDistroRe.FindStringSubmatch(comment); m != nil {
			name = m[1]
		}
		if name != "" && !seen[name] && pkgMap[name] != nil {
			seen[name] = true
			pkgs = append(pkgs, *pkgMap[name])
		}
	}
	for _, c := range crit.Criterions {
		add(c.Comment)
	}
	for _, cr := range crit.Criteria {
		for _, c := range cr.Criterions {
			add(c.Comment)
		}
	}
	return pkgs
}

// ubuntuOVALDefs is the minimal XML structure for Ubuntu/Debian OVAL.
type ubuntuOVALDefs struct {
	Definitions []ubuntuOVALDef `xml:"definitions>definition"`
}

type ubuntuOVALDef struct {
	Class    string            `xml:"class,attr"`
	Metadata ubuntuOVALMeta    `xml:"metadata"`
	Criteria ubuntuOVALCritTop `xml:"criteria"`
}

type ubuntuOVALMeta struct {
	References []ubuntuOVALRef    `xml:"reference"`
	Advisory   ubuntuOVALAdvisory `xml:"advisory"`
}

type ubuntuOVALRef struct {
	Source string `xml:"source,attr"`
	RefID  string `xml:"ref_id,attr"`
}

type ubuntuOVALAdvisory struct {
	Severity string          `xml:"severity"`
	CVEs     []ubuntuOVALCVE `xml:"cve"`
}

type ubuntuOVALCVE struct {
	Priority string `xml:"priority,attr"`
}

type ubuntuOVALCritTop struct {
	ExtendDef  []ubuntuOVALExtend    `xml:"extend_definition"`
	Criteria   []ubuntuOVALCriteria  `xml:"criteria"`
	Criterions []ubuntuOVALCriterion `xml:"criterion"`
}

type ubuntuOVALCriteria struct {
	Criterions []ubuntuOVALCriterion `xml:"criterion"`
}

type ubuntuOVALExtend struct {
	Comment string `xml:"comment,attr"`
}

type ubuntuOVALCriterion struct {
	Comment string `xml:"comment,attr"`
}

// ParseUbuntuOVAL parses an Ubuntu/Debian OVAL file (bzip2 or plain XML)
// and returns a map of CVE ID → UbuntuCVERecord.
func ParseUbuntuOVAL(ovalPath string) (map[string]RHELCVERecord, error) {
	f, err := os.Open(ovalPath) // #nosec G304
	if err != nil {
		return nil, fmt.Errorf("opening OVAL: %w", err)
	}
	defer f.Close() //nolint:errcheck

	var r io.Reader = f
	if strings.HasSuffix(strings.ToLower(ovalPath), ".bz2") {
		r = bzip2.NewReader(f)
	}

	var defs ubuntuOVALDefs
	if err := xml.NewDecoder(boundDecompressed(r)).Decode(&defs); err != nil {
		return nil, fmt.Errorf("parsing OVAL XML: %w", err)
	}
	if len(defs.Definitions) == 0 {
		return nil, fmt.Errorf("OVAL file %s parsed 0 definitions — truncated, corrupt, or not an OVAL feed", ovalPath)
	}

	result := make(map[string]RHELCVERecord, len(defs.Definitions)/4)

	for _, def := range defs.Definitions {
		if def.Class != "vulnerability" {
			continue
		}

		// Extract CVE ID
		var cveID string
		for _, ref := range def.Metadata.References {
			if strings.EqualFold(ref.Source, "CVE") && strings.HasPrefix(ref.RefID, "CVE-") {
				cveID = strings.ToUpper(ref.RefID)
				break
			}
		}
		if cveID == "" {
			continue
		}

		// Extract priority → pseudo-CVSS score
		priority := strings.ToLower(strings.TrimSpace(def.Metadata.Advisory.Severity))
		for _, c := range def.Metadata.Advisory.CVEs {
			if c.Priority != "" {
				priority = strings.ToLower(c.Priority)
				break
			}
		}
		cvss := ubuntuPriorityToCVSS[priority]
		// Title-case the priority for display. Guard the empty case: a
		// vulnerability def with no severity and no <cve priority> would
		// otherwise panic on priority[:1] (slice bounds out of range).
		severity := priority
		if priority != "" {
			severity = strings.ToUpper(priority[:1]) + strings.ToLower(priority[1:]) // Title case without deprecated strings.Title
		}

		// Extract package names from criterion comments
		var packages []string
		seen := map[string]bool{}
		addPkg := func(comment string) {
			if m := pkgInDistroRe.FindStringSubmatch(comment); m != nil {
				pkg := m[1]
				if !seen[pkg] {
					seen[pkg] = true
					packages = append(packages, pkg)
				}
			}
		}
		for _, c := range def.Criteria.Criterions {
			addPkg(c.Comment)
		}
		for _, cr := range def.Criteria.Criteria {
			for _, c := range cr.Criterions {
				addPkg(c.Comment)
			}
		}

		if len(packages) == 0 {
			continue
		}

		rec := RHELCVERecord{
			CVEID:      cveID,
			CVSS3:      cvss,
			Severity:   severity,
			Components: packages,
			State:      "Affected",
		}
		if existing, ok := result[cveID]; !ok || cvss > existing.CVSS3 {
			result[cveID] = rec
		}
	}

	return result, nil
}

// QueryInstalledDPKG returns installed packages on Debian/Ubuntu via dpkg-query.
func QueryInstalledDPKG(ctx context.Context) ([]InstalledPackage, error) {
	cmd := exec.CommandContext(ctx, resolveDpkgQuery("dpkg-query"), "-W", "-f=${Package}\t${Version}\n") //nolint:gosec // G204: hardcoded binary // NOSONAR
	cmd.Env = platform.HardenedEnv()
	cmd.WaitDelay = platform.ExecWaitDelay
	out, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("dpkg-query failed: %w", err)
	}
	var pkgs []InstalledPackage
	for line := range strings.SplitSeq(strings.TrimSpace(string(out)), "\n") {
		fields := strings.SplitN(line, "\t", 2)
		if len(fields) < 1 || fields[0] == "" {
			continue
		}
		p := InstalledPackage{Name: fields[0]}
		if len(fields) == 2 {
			p.EVR = fields[1]
		}
		pkgs = append(pkgs, p)
	}
	return pkgs, nil
}

// ScanUbuntuOVALPackages parses an Ubuntu/Debian OVAL file and cross-references
// with installed dpkg packages. Returns CVE findings bucketed by priority.
//
// Version-aware suppression: when the OVAL criterion carries a fixed version
// ("X DPKG is earlier than VERSION"), a package whose installed version is
// already >= fixedIn is silently skipped — the system is patched for that CVE.
// When no fixed version is known ("X package in Y is affected and may need
// fixing"), the package is flagged if installed: conservative, matches prior
// behaviour, avoids a false-OK on a CVE with no fix yet.
func ScanUbuntuOVALPackages(ctx context.Context, ovalPath string) ([]OVALCVSSResult, error) {
	entries, installed, err := loadUbuntuOVALAndInstalled(ctx, ovalPath)
	if err != nil {
		return nil, err
	}

	var results []OVALCVSSResult
	for _, entry := range entries {
		allComponents, vulnerable := ubuntuEntryMatches(entry, installed)
		if len(vulnerable) == 0 {
			continue
		}
		installedNames := make([]string, len(vulnerable))
		for i, v := range vulnerable {
			installedNames[i] = v.name
		}
		results = append(results, OVALCVSSResult{
			CVEID:      entry.cveID,
			CVSS3:      entry.cvss,
			Severity:   entry.severity,
			State:      "Affected",
			Components: allComponents,
			Installed:  installedNames,
		})
	}

	sortOVALResults(results)
	return results, nil
}

// loadUbuntuOVALAndInstalled parses ovalPath and queries installed dpkg
// packages — the shared first half of ScanUbuntuOVALPackages (bulk scan) and
// checkCVEFromUbuntuOVAL (single-CVE check).
func loadUbuntuOVALAndInstalled(ctx context.Context, ovalPath string) ([]ubuntuVulnEntry, map[string]string, error) {
	f, err := os.Open(ovalPath) // #nosec G304
	if err != nil {
		return nil, nil, fmt.Errorf("opening OVAL: %w", err)
	}
	defer f.Close() //nolint:errcheck

	var r io.Reader = f
	if strings.HasSuffix(strings.ToLower(ovalPath), ".bz2") {
		r = bzip2.NewReader(f)
	}

	entries, err := parseUbuntuOVALVersionAware(boundDecompressed(r))
	if err != nil {
		return nil, nil, err
	}

	pkgs, err := QueryInstalledDPKG(ctx)
	if err != nil {
		return nil, nil, fmt.Errorf("querying installed packages: %w", err)
	}
	installed := make(map[string]string, len(pkgs)) // name (lower) → EVR
	for _, p := range pkgs {
		installed[strings.ToLower(p.Name)] = p.EVR
	}
	return entries, installed, nil
}

// ubuntuVulnerableMatch is a package from an OVAL entry found both installed
// and not yet patched against the entry's CVE.
type ubuntuVulnerableMatch struct {
	name      string
	installed string
	fixedIn   string
}

// ubuntuEntryMatches evaluates entry's packages against the installed dpkg
// map (name lower → EVR) and returns (all named components, currently
// vulnerable installed packages). Shared by ScanUbuntuOVALPackages and
// checkCVEFromUbuntuOVAL so both apply identical version-aware suppression —
// see ScanUbuntuOVALPackages's doc comment for the suppression rule.
func ubuntuEntryMatches(entry ubuntuVulnEntry, installed map[string]string) (allComponents []string, vulnerable []ubuntuVulnerableMatch) {
	for _, pkg := range entry.pkgs {
		allComponents = append(allComponents, pkg.name)
		installedEVR, ok := installed[strings.ToLower(pkg.name)]
		if !ok || installedEVR == "" || installedEVR == "(none)" {
			// Not installed, or in config-files/half-installed dpkg state.
			// Treat identically to "package absent" — do not suppress the CVE.
			continue
		}
		if pkg.fixedIn != "" && CompareDpkg(installedEVR, pkg.fixedIn) >= 0 {
			continue // already patched
		}
		vulnerable = append(vulnerable, ubuntuVulnerableMatch{
			name: pkg.name, installed: installedEVR, fixedIn: pkg.fixedIn,
		})
	}
	return allComponents, vulnerable
}

// checkCVEFromUbuntuOVAL is CheckCVEFromOVAL's Ubuntu/Debian counterpart: the
// RHEL/SUSE path's rpminfo_test/object/state criteria walk and QueryInstalledRPM
// cross-reference don't apply to a dpkg-based host, so this parses the
// Ubuntu/Debian OVAL schema directly (parseUbuntuOVALVersionAware, the same
// parser ScanUbuntuOVALPackages uses) and narrows to the single CVE the caller
// asked about, rather than returning every vulnerable CVE.
func checkCVEFromUbuntuOVAL(ctx context.Context, ovalPath, cveID string) (*OVALResult, error) {
	entries, installed, err := loadUbuntuOVALAndInstalled(ctx, ovalPath)
	if err != nil {
		return nil, fmt.Errorf("loading OVAL: %w", err)
	}

	result := &OVALResult{CVE: cveID}
	var matched *ubuntuVulnEntry
	for i := range entries {
		if entries[i].cveID == cveID {
			matched = &entries[i]
			break
		}
	}
	if matched == nil {
		return result, nil // Found stays false: no definition for this CVE
	}
	result.Found = true
	result.Severity = matched.severity

	_, vulnerable := ubuntuEntryMatches(*matched, installed)
	for _, v := range vulnerable {
		result.Packages = append(result.Packages, OVALPackageMatch{
			Name:      v.name,
			Installed: v.installed,
			FixedIn:   v.fixedIn,
		})
	}
	return result, nil
}
