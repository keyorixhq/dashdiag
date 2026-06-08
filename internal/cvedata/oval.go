//go:build linux

package cvedata

import (
	"compress/bzip2"
	"context"
	"encoding/xml"
	"fmt"
	"io"
	"os"
	"regexp"
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
	Severity string `xml:"severity"`
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
	dec := xml.NewDecoder(r)
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

// ScanSUSEOVALPackages parses a SUSE/openSUSE patch OVAL file and
// cross-references with installed RPM packages.
func ScanSUSEOVALPackages(ctx context.Context, ovalPath string) ([]OVALCVSSResult, error) {
	oval, err := loadOVAL(ovalPath)
	if err != nil {
		return nil, err
	}

	// Build object lookup: object_id → package name
	objName := make(map[string]string, len(oval.Objects))
	for _, o := range oval.Objects {
		objName[o.ID] = o.Name
	}
	// Build test lookup: test_id → object_id
	testObj := make(map[string]string, len(oval.Tests))
	for _, t := range oval.Tests {
		testObj[t.ID] = t.ObjectRef()
	}

	// Get installed RPM packages
	pkgs, err := QueryInstalledRPM(ctx)
	if err != nil {
		return nil, fmt.Errorf("querying installed packages: %w", err)
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

		// Extract CVE IDs
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

		// Collect package names from criteria (via test→object map or comment)
		pkgSet := map[string]bool{}
		collectSUSEPkgs(def.Criteria, testObj, objName, pkgSet)

		// Cross-reference with installed packages
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

		// One result per CVE ID
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

	sortOVALResults(results)
	return results, nil
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
