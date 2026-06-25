//go:build linux

package cvedata

import (
	"os"
	"path/filepath"
	"testing"
)

// buildSUSEVulnDef returns a synthetic class="vulnerability" definition with the
// real openSUSE shape: AND( platform-guard, OR( AND( version-test, signature-test ) ) ).
// fixedEVR is the "less than" threshold on package "foo".
func buildSUSEVulnDef(fixedEVR string) *ovalDefinitions {
	return &ovalDefinitions{
		Definitions: []ovalDefinition{{
			ID:    "oval:test:def:1",
			Class: "vulnerability",
			Metadata: ovalMetadata{
				References: []ovalReference{
					{Source: "CVE", RefID: "Mitre CVE-2025-9999"},
					{Source: "SUSE CVE", RefID: "SUSE CVE-2025-9999"},
				},
				Advisory: ovalAdvisory{
					Severity: "important",
					CVEs:     []ovalAdvCVE{{CVSS3: "7.8/CVSS:3.1/AV:L"}},
				},
			},
			Criteria: ovalCriteria{
				Criterion: []ovalCriterion{{TestRef: "tst:guard"}},
				Criteria: []ovalCriteria{{
					Criteria: []ovalCriteria{{
						Criterion: []ovalCriterion{
							{TestRef: "tst:ver"},
							{TestRef: "tst:sig"},
						},
					}},
				}},
			},
		}},
		Tests: []ovalRPMTest{
			{ID: "tst:guard", Object: ovalObjectRef{Ref: "obj:os"}, State: ovalStateRef{Ref: "ste:os"}},
			{ID: "tst:ver", Object: ovalObjectRef{Ref: "obj:foo"}, State: ovalStateRef{Ref: "ste:ver"}},
			{ID: "tst:sig", Object: ovalObjectRef{Ref: "obj:foo"}, State: ovalStateRef{Ref: "ste:sig"}},
		},
		Objects: []ovalRPMObject{
			{ID: "obj:os", Name: "openSUSE-release"},
			{ID: "obj:foo", Name: "foo"},
		},
		States: []ovalRPMState{
			{ID: "ste:os", EVR: ovalEVR{Value: "16.0", Operation: "greater than or equal"}},
			{ID: "ste:ver", EVR: ovalEVR{Value: fixedEVR, Operation: "less than"}},
			{ID: "ste:sig", EVR: ovalEVR{Value: ""}}, // signature test — no version
		},
	}
}

func TestScanSUSEVulnClass_FlagsVersionGapIgnoringGuards(t *testing.T) {
	oval := buildSUSEVulnDef("1.0-2")
	// foo installed BELOW the fixed version → vulnerable. openSUSE-release present
	// but must never be flagged (platform marker + guard op is not "less than").
	pkgs := []InstalledPackage{
		{Name: "foo", EVR: "0:1.0-1"},
		{Name: "openSUSE-release", EVR: "0:16.0-1"},
	}
	got := scanSUSEVulnClass(oval, pkgs)
	if len(got) != 1 {
		t.Fatalf("expected 1 result, got %d: %+v", len(got), got)
	}
	if got[0].CVEID != "CVE-2025-9999" {
		t.Errorf("CVE = %q, want CVE-2025-9999", got[0].CVEID)
	}
	if got[0].CVSS3 != 7.8 {
		t.Errorf("CVSS3 = %v, want 7.8 (from advisory cvss3)", got[0].CVSS3)
	}
	if len(got[0].Installed) != 1 || got[0].Installed[0] != "foo" {
		t.Errorf("Installed = %v, want [foo] (guard/marker must not appear)", got[0].Installed)
	}
}

func TestScanSUSEVulnClass_PatchedHostIsClean(t *testing.T) {
	oval := buildSUSEVulnDef("1.0-2")
	// foo installed AT the fixed version → not below → not vulnerable.
	pkgs := []InstalledPackage{{Name: "foo", EVR: "0:1.0-2"}}
	if got := scanSUSEVulnClass(oval, pkgs); len(got) != 0 {
		t.Errorf("patched host should be clean, got %+v", got)
	}
}

func TestScanSUSEVulnClass_UninstalledPackageNotFlagged(t *testing.T) {
	oval := buildSUSEVulnDef("1.0-2")
	if got := scanSUSEVulnClass(oval, []InstalledPackage{{Name: "bar", EVR: "0:0.1-1"}}); len(got) != 0 {
		t.Errorf("package not installed must not be flagged, got %+v", got)
	}
}

func TestCVEsFromRefs(t *testing.T) {
	refs := []ovalReference{
		{Source: "CVE", RefID: "Mitre CVE-2025-1"},
		{Source: "SUSE CVE", RefID: "SUSE CVE-2025-1"}, // dup → collapsed
		{Source: "SUSE-SU", RefID: "SUSE-SU-2025:123-1"},
		{Source: "CVE", RefID: "Mitre CVE-2024-2"},
	}
	got := cvesFromRefs(refs)
	if len(got) != 2 || got[0] != "CVE-2025-1" || got[1] != "CVE-2024-2" {
		t.Errorf("cvesFromRefs = %v, want [CVE-2025-1 CVE-2024-2]", got)
	}
}

func TestParseCVSS3Prefix(t *testing.T) {
	cases := map[string]float64{
		"8.6/CVSS:3.1/AV:N/AC:L": 8.6,
		"9.8":                    9.8,
		"":                       0,
		"n/a":                    0,
	}
	for in, want := range cases {
		if got := parseCVSS3Prefix(in); got != want {
			t.Errorf("parseCVSS3Prefix(%q) = %v, want %v", in, got, want)
		}
	}
}

func TestSniffOVALVendor(t *testing.T) {
	dir := t.TempDir()
	write := func(name, content string) string {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
		return p
	}
	// A SUSE feed saved under a neutral name must still sniff as "suse".
	suse := write("oval.xml", `<?xml version="1.0"?><oval_definitions><definition id="oval:org.opensuse.security:def:1"/></oval_definitions>`)
	if v := sniffOVALVendor(suse); v != "suse" {
		t.Errorf("sniffOVALVendor(suse content) = %q, want suse", v)
	}
	rhel := write("feed.xml", `<?xml version="1.0"?><oval_definitions><definition id="oval:com.redhat.rhsa:def:1"/></oval_definitions>`)
	if v := sniffOVALVendor(rhel); v != "rhel" {
		t.Errorf("sniffOVALVendor(rhel content) = %q, want rhel", v)
	}
	ubuntu := write("u.xml", `<?xml version="1.0"?><oval_definitions><definition id="oval:com.ubuntu.noble:def:1"/></oval_definitions>`)
	if v := sniffOVALVendor(ubuntu); v != "ubuntu" {
		t.Errorf("sniffOVALVendor(ubuntu content) = %q, want ubuntu", v)
	}
}
