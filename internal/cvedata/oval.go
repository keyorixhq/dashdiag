//go:build linux

package cvedata

import (
	"compress/bzip2"
	"context"
	"encoding/xml"
	"fmt"
	"io"
	"os"
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
}

type ovalRPMTest struct {
	ID        string `xml:"id,attr"`
	ObjectRef string `xml:"object>object_ref,attr"`
	StateRef  string `xml:"state>state_ref,attr"`
}

type ovalRPMObject struct {
	ID   string `xml:"id,attr"`
	Name string `xml:"name"`
}

type ovalRPMState struct {
	ID        string `xml:"id,attr"`
	EVR       string `xml:"evr"`
	Operation string `xml:"evr>operation,attr"`
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
	var matchDef *ovalDefinition
	for i := range oval.Definitions {
		def := &oval.Definitions[i]
		for _, ref := range def.Metadata.References {
			if strings.EqualFold(ref.RefID, cveID) {
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
		obj, ok := objects[test.ObjectRef]
		if !ok {
			continue
		}
		state, ok := states[test.StateRef]
		if !ok {
			continue
		}
		installedEVR, present := installed[obj.Name]
		if !present {
			continue // package not installed → not affected
		}
		fixedIn := state.EVR
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
	return &oval, nil
}
