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
)

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
	if err := xml.NewDecoder(r).Decode(&defs); err != nil {
		return nil, fmt.Errorf("parsing OVAL XML: %w", err)
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
		severity := strings.ToUpper(priority[:1]) + strings.ToLower(priority[1:]) // Title case without deprecated strings.Title

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
	cmd := exec.CommandContext(ctx, "dpkg-query", "-W", "-f=${Package}\t${Version}\n") // #nosec G204
	out, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("dpkg-query failed: %w", err)
	}
	var pkgs []InstalledPackage
	for _, line := range strings.Split(strings.TrimSpace(string(out)), "\n") {
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

// ScanUbuntuOVALPackages parses an Ubuntu OVAL file and cross-references
// with installed dpkg packages. Returns CVE findings bucketed by priority.
func ScanUbuntuOVALPackages(ctx context.Context, ovalPath string) ([]OVALCVSSResult, error) {
	cveMap, err := ParseUbuntuOVAL(ovalPath)
	if err != nil {
		return nil, err
	}

	pkgs, err := QueryInstalledDPKG(ctx)
	if err != nil {
		return nil, fmt.Errorf("querying installed packages: %w", err)
	}
	installed := make(map[string]bool, len(pkgs))
	for _, p := range pkgs {
		installed[strings.ToLower(p.Name)] = true
	}

	var results []OVALCVSSResult
	for _, rec := range cveMap {
		var installedMatches []string
		for _, comp := range rec.Components {
			if installed[strings.ToLower(comp)] {
				installedMatches = append(installedMatches, comp)
			}
		}
		if len(installedMatches) == 0 {
			continue
		}
		results = append(results, OVALCVSSResult{
			CVEID:      rec.CVEID,
			CVSS3:      rec.CVSS3,
			Severity:   rec.Severity,
			State:      rec.State,
			Components: rec.Components,
			Installed:  installedMatches,
		})
	}

	sortOVALResults(results)
	return results, nil
}
