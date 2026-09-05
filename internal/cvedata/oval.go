//go:build linux

package cvedata

import (
	"compress/bzip2"
	"context"
	"encoding/xml"
	"fmt"
	"io"
	"math"
	"os"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

// --- Minimal OVAL XML structs (SUSE/openSUSE OVAL schema) ---

type ovalDefinitions struct {
	Definitions []ovalDefinition `xml:"definitions>definition"`
	Tests       []ovalRPMTest    `xml:"tests>rpminfo_test"`
	Objects     []ovalRPMObject  `xml:"objects>rpminfo_object"`
	States      []ovalRPMState   `xml:"states>rpminfo_state"`
}

type ovalDefinition struct {
	ID       string       `xml:"id,attr"`
	Class    string       `xml:"class,attr"`
	Metadata ovalMetadata `xml:"metadata"`
	Criteria ovalCriteria `xml:"criteria"`
}

type ovalMetadata struct {
	Title      string          `xml:"title"`
	References []ovalReference `xml:"reference"`
	Advisory   ovalAdvisory    `xml:"advisory"`
}

type ovalReference struct {
	Source string `xml:"source,attr"`
	RefID  string `xml:"ref_id,attr"`
}

type ovalAdvisory struct {
	Severity string       `xml:"severity"`
	CVEs     []ovalAdvCVE `xml:"cve"`
}

// ovalAdvCVE is a <cve> entry under <advisory>. The cvss3 attribute is a vector
// string like "8.6/CVSS:3.1/AV:N/..."; we take the leading base score.
type ovalAdvCVE struct {
	CVSS3 string `xml:"cvss3,attr"`
}

// maxCVSS3 returns the highest CVSS3 base score across the advisory's <cve>
// entries (SUSE and NVD often score the same CVE differently), or 0 if none parse.
func (a ovalAdvisory) maxCVSS3() float64 {
	var best float64
	for _, c := range a.CVEs {
		if v := parseCVSS3Prefix(c.CVSS3); v > best {
			best = v
		}
	}
	return best
}

// parseCVSS3Prefix pulls the leading base score from a CVSS3 vector string:
// "8.6/CVSS:3.1/AV:N/..." → 8.6. Returns 0 on anything unparseable.
func parseCVSS3Prefix(s string) float64 {
	s = strings.TrimSpace(s)
	if i := strings.IndexByte(s, '/'); i >= 0 {
		s = s[:i]
	}
	// strconv.ParseFloat treats "NaN" as a successful parse, not an error — a
	// NaN score would fail every score>=N severity-bucket comparison
	// downstream and silently understate a CVE's severity instead of erroring.
	v, err := strconv.ParseFloat(s, 64)
	if err != nil || math.IsNaN(v) || math.IsInf(v, 0) {
		return 0
	}
	return v
}

type ovalCriteria struct {
	Criteria  []ovalCriteria  `xml:"criteria"`
	Criterion []ovalCriterion `xml:"criterion"`
}

type ovalCriterion struct {
	TestRef string `xml:"test_ref,attr"`
	Comment string `xml:"comment,attr"` // e.g. "go1.25-1.25.5-1.1 is installed"
}

type ovalRPMTest struct {
	ID     string        `xml:"id,attr"`
	Object ovalObjectRef `xml:"object"`
	State  ovalStateRef  `xml:"state"`
}

func (t ovalRPMTest) ObjectRef() string { return t.Object.Ref }
func (t ovalRPMTest) StateRef() string  { return t.State.Ref }

type ovalObjectRef struct {
	Ref string `xml:"object_ref,attr"`
}

type ovalStateRef struct {
	Ref string `xml:"state_ref,attr"`
}

type ovalRPMObject struct {
	ID   string `xml:"id,attr"`
	Name string `xml:"name"`
}

type ovalRPMState struct {
	ID  string  `xml:"id,attr"`
	EVR ovalEVR `xml:"evr"`
}

type ovalEVR struct {
	Value     string `xml:",chardata"`
	Operation string `xml:"operation,attr"`
}

// CheckCVEFromOVAL checks a CVE using an OVAL file (bzip2 or plain XML).
// The OVAL file can be downloaded from:
//
//	SLES/openSUSE: https://ftp.suse.com/pub/projects/security/oval/
//	RHEL/Rocky:    https://www.redhat.com/security/data/oval/
func CheckCVEFromOVAL(ctx context.Context, ovalPath string, cveID string) (*OVALResult, error) {
	cveID = strings.ToUpper(strings.TrimSpace(cveID))

	// Ubuntu/Debian OVAL feeds use a different XML schema (no rpminfo_test/
	// object/state criteria tree) and are cross-referenced via dpkg, not rpm —
	// same vendor dispatch ScanOVALPackages already applies for the bulk scan.
	// Without this, a staged Ubuntu/Debian feed was silently parsed as if it
	// were RHEL-shaped, found no matching definition, and always reported
	// "not found" regardless of the feed's actual content.
	if detectOVALVendor(ovalPath) == "ubuntu" {
		return checkCVEFromUbuntuOVAL(ctx, ovalPath, cveID)
	}

	result := &OVALResult{CVE: cveID}

	oval, err := loadOVAL(ovalPath)
	if err != nil {
		return nil, fmt.Errorf("loading OVAL: %w", err)
	}

	// Build lookup maps
	tests := make(map[string]*ovalRPMTest, len(oval.Tests))
	for i := range oval.Tests {
		tests[oval.Tests[i].ID] = &oval.Tests[i]
	}
	objects := make(map[string]*ovalRPMObject, len(oval.Objects))
	for i := range oval.Objects {
		objects[oval.Objects[i].ID] = &oval.Objects[i]
	}
	states := make(map[string]*ovalRPMState, len(oval.States))
	for i := range oval.States {
		states[oval.States[i].ID] = &oval.States[i]
	}

	// Find definition matching our CVE
	// SUSE OVAL uses ref_id like "Mitre CVE-XXXX" or "SUSE CVE-XXXX"
	// so we check if ref_id equals OR contains the CVE ID.
	var matchDef *ovalDefinition
	for i := range oval.Definitions {
		def := &oval.Definitions[i]
		for _, ref := range def.Metadata.References {
			if strings.EqualFold(ref.RefID, cveID) ||
				strings.Contains(strings.ToUpper(ref.RefID), strings.ToUpper(cveID)) {
				matchDef = def
				break
			}
		}
		if matchDef != nil {
			break
		}
	}

	if matchDef == nil {
		result.Found = false
		return result, nil
	}

	result.Found = true
	result.Summary = matchDef.Metadata.Title
	result.Severity = matchDef.Metadata.Advisory.Severity

	// Get installed packages
	installed, err := QueryInstalledRPM(ctx)
	if err != nil {
		return result, fmt.Errorf("querying installed packages: %w", err)
	}
	installedMap := make(map[string]string, len(installed))
	for _, p := range installed {
		installedMap[p.Name] = p.EVR
	}

	// Walk criteria tree and evaluate each criterion
	collectMatches(matchDef.Criteria, tests, objects, states, installedMap, result)

	return result, nil
}

// collectMatches walks the criteria tree recursively.
func collectMatches(criteria ovalCriteria, tests map[string]*ovalRPMTest,
	objects map[string]*ovalRPMObject, states map[string]*ovalRPMState,
	installed map[string]string, result *OVALResult) {

	for _, criterion := range criteria.Criterion {
		test, ok := tests[criterion.TestRef]
		if !ok {
			continue
		}
		obj, ok := objects[test.ObjectRef()]
		if !ok {
			continue
		}
		state, ok := states[test.StateRef()]
		if !ok {
			continue
		}
		installedEVR, present := installed[obj.Name]
		if !present {
			continue // package not installed → not affected
		}
		fixedIn := state.EVR.Value
		if IsVulnerable(installedEVR, fixedIn) {
			result.Packages = append(result.Packages, OVALPackageMatch{
				Name:      obj.Name,
				Installed: installedEVR,
				FixedIn:   fixedIn,
			})
		}
	}
	// Recurse into nested criteria
	for _, sub := range criteria.Criteria {
		collectMatches(sub, tests, objects, states, installed, result)
	}
}

// loadOVAL reads and parses an OVAL XML file (auto-detects bzip2).
func loadOVAL(path string) (*ovalDefinitions, error) {
	f, err := os.Open(path) // #nosec G304 -- user-supplied path intentional
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var r io.Reader = f
	if strings.HasSuffix(strings.ToLower(path), ".bz2") {
		r = bzip2.NewReader(f)
	}

	var oval ovalDefinitions
	dec := xml.NewDecoder(boundDecompressed(r))
	if err := dec.Decode(&oval); err != nil {
		return nil, fmt.Errorf("parsing OVAL XML: %w", err)
	}
	// A real OVAL feed always contains definitions. Zero means the file was
	// truncated, decompressed wrong, or isn't OVAL — fail loudly rather than
	// let every CVE check silently come back "not found / not vulnerable".
	if len(oval.Definitions) == 0 {
		return nil, fmt.Errorf("OVAL file %s parsed 0 definitions — truncated, corrupt, or not an OVAL feed", path)
	}
	return &oval, nil
}

// suSeverityToCVSS maps SUSE/openSUSE severity strings to pseudo-CVSS3 scores.
var suSeverityToCVSS = map[string]float64{
	"critical":  9.5,
	"important": 8.0,
	"moderate":  5.0,
	"low":       2.0,
}

// suSeverityRe matches the trailing severity label in a SUSE patch title:
// "Security update for go1.25 (Important)" → "important"
var suSeverityRe = regexp.MustCompile(`\((\w+)\)\s*$`)

// suPkgFromCommentRe extracts the package name from a criterion comment:
// "go1.25-1.25.5-160000.1.1 is installed" → "go1.25"
var suPkgFromCommentRe = regexp.MustCompile(`^([\w.+:-]+?)-\d`)

// ScanSUSEOVALPackages parses a SUSE/openSUSE OVAL file and cross-references it
// with installed RPM packages. SUSE ships two feed shapes and dsd handles both:
//
//   - class="patch" feeds (e.g. *.patch.xml): one definition per advisory; a
//     definition applies if the named package is installed (presence-based).
//   - class="vulnerability" feeds (the DEFAULT feed at ftp.suse.com, what
//     `dsd cve info` tells users to download): one definition per CVE, whose
//     criteria carry a "less than fixed-version" test. Presence alone is not
//     enough — we must compare versions.
//
// Both class shapes are scanned and their findings unioned: the standard feed
// (the DEFAULT at ftp.suse.com, what `dsd cve info` tells users to download) is
// 100% vulnerability-class, where the patch loop matches nothing — so before
// this, the scan reported a green "no vulnerable packages found" false-OK on
// that exact feed. The two scanners process disjoint definition sets, so the
// union can't double-count within a class. Validated against `oscap oval eval`
// and `zypper lp` on real openSUSE Leap 16.0 (zero false negatives vs the
// reference evaluator; matched zypper's needed-security set where oscap's
// signature gate masked it).
func ScanSUSEOVALPackages(ctx context.Context, ovalPath string) ([]OVALCVSSResult, error) {
	oval, err := loadOVAL(ovalPath)
	if err != nil {
		return nil, err
	}

	pkgs, err := QueryInstalledRPM(ctx)
	if err != nil {
		return nil, fmt.Errorf("querying installed packages: %w", err)
	}

	// Scan BOTH class shapes and union, rather than early-returning on the first
	// non-empty one — a feed that mixes patch- and vulnerability-class defs is
	// then fully covered instead of having one half silently dropped.
	// "Never under-report" is the invariant for a security scan.
	results := scanSUSEPatchClass(oval, pkgs)
	results = append(results, scanSUSEVulnClass(oval, pkgs)...)
	results = dedupOVALByCVE(results)
	sortOVALResults(results)
	return results, nil
}

// dedupOVALByCVE collapses results sharing a CVE ID — possible only if a feed
// carries the same CVE in both a patch and a vulnerability definition — keeping
// the first occurrence and preserving order.
func dedupOVALByCVE(in []OVALCVSSResult) []OVALCVSSResult {
	if len(in) < 2 {
		return in
	}
	seen := make(map[string]bool, len(in))
	out := make([]OVALCVSSResult, 0, len(in))
	for _, r := range in {
		if seen[r.CVEID] {
			continue
		}
		seen[r.CVEID] = true
		out = append(out, r)
	}
	return out
}

// scanSUSEPatchClass implements the presence-based scan for class="patch" feeds.
func scanSUSEPatchClass(oval *ovalDefinitions, pkgs []InstalledPackage) []OVALCVSSResult {
	objName := make(map[string]string, len(oval.Objects))
	for _, o := range oval.Objects {
		objName[o.ID] = o.Name
	}
	testObj := make(map[string]string, len(oval.Tests))
	for _, t := range oval.Tests {
		testObj[t.ID] = t.ObjectRef()
	}
	installed := make(map[string]bool, len(pkgs))
	for _, p := range pkgs {
		installed[strings.ToLower(p.Name)] = true
	}

	var results []OVALCVSSResult
	for _, def := range oval.Definitions {
		if def.Class != "patch" {
			continue
		}

		var cveIDs []string
		for _, ref := range def.Metadata.References {
			if strings.EqualFold(ref.Source, "CVE") && strings.HasPrefix(ref.RefID, "CVE-") {
				cveIDs = append(cveIDs, strings.ToUpper(ref.RefID))
			}
		}
		if len(cveIDs) == 0 {
			continue
		}

		// Extract severity from title: "Security update for X (Important)"
		severity := "Unknown"
		cvss := 0.0
		if m := suSeverityRe.FindStringSubmatch(def.Metadata.Title); m != nil {
			sev := strings.ToLower(m[1])
			severity = strings.ToUpper(sev[:1]) + sev[1:]
			cvss = suSeverityToCVSS[sev]
		}

		pkgSet := map[string]bool{}
		collectSUSEPkgs(def.Criteria, testObj, objName, pkgSet)

		var installedMatches []string
		for pkg := range pkgSet {
			// Skip OS-version marker packages — they're in every SUSE patch definition
			// as a "platform is installed" criterion, not as actual affected packages.
			if isSUSEPlatformMarker(pkg) {
				continue
			}
			if installed[strings.ToLower(pkg)] {
				installedMatches = append(installedMatches, pkg)
			}
		}
		if len(installedMatches) == 0 {
			continue
		}

		for _, cveID := range cveIDs {
			results = append(results, OVALCVSSResult{
				CVEID:      cveID,
				CVSS3:      cvss,
				Severity:   severity,
				State:      "Affected",
				Components: keys(pkgSet),
				Installed:  installedMatches,
			})
		}
	}
	return results
}

// susePkgFixTest pairs an rpminfo test's package name with the fixed-version EVR
// from its referenced state (empty EVR for signature/non-versioned tests).
type susePkgFixTest struct {
	pkg   string
	fixed ovalEVR
}

// scanSUSEVulnClass implements the version-aware scan for class="vulnerability"
// feeds: a definition fires when an installed package's EVR is below the fixed
// version named in a "less than" test. This mirrors `oscap`'s fix-test semantics
// (minus the signature/platform AND-guards, which dsd deliberately ignores — that
// can only over-flag, never miss; proven against oscap on openSUSE Leap 16.0).
func scanSUSEVulnClass(oval *ovalDefinitions, pkgs []InstalledPackage) []OVALCVSSResult {
	objName := make(map[string]string, len(oval.Objects))
	for _, o := range oval.Objects {
		objName[o.ID] = o.Name
	}
	stateEVR := make(map[string]ovalEVR, len(oval.States))
	for _, s := range oval.States {
		stateEVR[s.ID] = s.EVR
	}
	// test_id → (object name, fixed EVR) for tests that carry a versioned state.
	tests := make(map[string]susePkgFixTest, len(oval.Tests))
	for _, t := range oval.Tests {
		vt := susePkgFixTest{pkg: objName[t.ObjectRef()]}
		if ev, ok := stateEVR[t.StateRef()]; ok {
			vt.fixed = ev
		}
		tests[t.ID] = vt
	}
	installed := make(map[string]string, len(pkgs))
	for _, p := range pkgs {
		installed[p.Name] = p.EVR
	}

	var results []OVALCVSSResult
	for i := range oval.Definitions {
		def := &oval.Definitions[i]
		if def.Class != "vulnerability" {
			continue
		}
		cveIDs := cvesFromRefs(def.Metadata.References)
		if len(cveIDs) == 0 {
			continue
		}
		matched := map[string]string{}
		collectSUSEVulnMatches(def.Criteria, tests, installed, matched)
		if len(matched) == 0 {
			continue
		}

		severity := "Unknown"
		if def.Metadata.Advisory.Severity != "" {
			s := strings.ToLower(def.Metadata.Advisory.Severity)
			severity = strings.ToUpper(s[:1]) + s[1:]
		}
		cvss := def.Metadata.Advisory.maxCVSS3()
		if cvss == 0 {
			cvss = suSeverityToCVSS[strings.ToLower(severity)]
		}

		names := make([]string, 0, len(matched))
		for n := range matched {
			names = append(names, n)
		}
		sort.Strings(names)
		for _, cveID := range cveIDs {
			results = append(results, OVALCVSSResult{
				CVEID:      cveID,
				CVSS3:      cvss,
				Severity:   severity,
				State:      "Affected",
				Components: names,
				Installed:  names,
			})
		}
	}
	return results
}

// collectSUSEVulnMatches walks the criteria tree and records every installed
// package whose version is below a "less than" fix test. It deliberately
// considers ONLY operation="less than" leaves — that excludes the platform
// guard (operation "greater than or equal"/"equals") and the signature tests
// (no EVR), which is what keeps a benign package from being mislabeled.
func collectSUSEVulnMatches(c ovalCriteria, tests map[string]susePkgFixTest,
	installed map[string]string, out map[string]string) {
	for _, cr := range c.Criterion {
		vt, ok := tests[cr.TestRef]
		if !ok || vt.fixed.Value == "" || vt.pkg == "" {
			continue
		}
		if !strings.Contains(strings.ToLower(vt.fixed.Operation), "less than") {
			continue // guard (>=/equals) or signature test — not a fix-version check
		}
		if isSUSEPlatformMarker(vt.pkg) {
			continue
		}
		if ins, present := installed[vt.pkg]; present && IsVulnerable(ins, vt.fixed.Value) {
			out[vt.pkg] = ins
		}
	}
	for _, sub := range c.Criteria {
		collectSUSEVulnMatches(sub, tests, installed, out)
	}
}

// cvesFromRefs extracts unique CVE IDs from OVAL references, handling SUSE's
// "Mitre CVE-XXXX" / "SUSE CVE-XXXX" ref_id forms.
func cvesFromRefs(refs []ovalReference) []string {
	seen := map[string]bool{}
	var out []string
	for _, ref := range refs {
		if !strings.EqualFold(ref.Source, "CVE") && !strings.Contains(strings.ToUpper(ref.RefID), "CVE-") {
			continue
		}
		for _, w := range strings.Fields(ref.RefID) {
			u := strings.ToUpper(w)
			if strings.HasPrefix(u, "CVE-") && !seen[u] {
				seen[u] = true
				out = append(out, u)
			}
		}
	}
	return out
}

// collectSUSEPkgs walks the criteria tree and collects package names.
func collectSUSEPkgs(c ovalCriteria, testObj, objName map[string]string, out map[string]bool) {
	for _, criterion := range c.Criterion {
		// Try via test→object map
		if objID, ok := testObj[criterion.TestRef]; ok {
			if name, ok := objName[objID]; ok && name != "" {
				out[name] = true
				continue
			}
		}
		// Fallback: extract package name from comment
		if m := suPkgFromCommentRe.FindStringSubmatch(criterion.Comment); m != nil {
			out[m[1]] = true
		}
	}
	for _, sub := range c.Criteria {
		collectSUSEPkgs(sub, testObj, objName, out)
	}
}

// keys returns the keys of a map[string]bool as a sorted slice.
func keys(m map[string]bool) []string {
	result := make([]string, 0, len(m))
	for k := range m {
		result = append(result, k)
	}
	return result
}

// isSUSEPlatformMarker returns true for SUSE OS-version sentinel packages
// that appear in every patch definition to assert the platform version.
// These are not actual vulnerable packages.
func isSUSEPlatformMarker(pkg string) bool {
	markers := []string{
		"Leap-release", "openSUSE-release", "SLES-release",
		"sles-release", "leap-release", "opensuse-release",
	}
	for _, m := range markers {
		if strings.EqualFold(pkg, m) {
			return true
		}
	}
	return false
}
