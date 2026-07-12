//go:build linux

package cvedata

import "testing"

// buildSUSEPatchDef returns a synthetic class="patch" definition: one
// advisory covering two CVEs, with a package criterion plus a platform-marker
// criterion (which must never be reported as an affected package).
func buildSUSEPatchDef(title string) *ovalDefinitions {
	return &ovalDefinitions{
		Definitions: []ovalDefinition{{
			Class: "patch",
			Metadata: ovalMetadata{
				Title: title,
				References: []ovalReference{
					{Source: "CVE", RefID: "CVE-2025-1111"},
					{Source: "CVE", RefID: "CVE-2025-2222"},
				},
			},
			Criteria: ovalCriteria{
				Criterion: []ovalCriterion{
					{TestRef: "tst:pkg", Comment: "go1.25-1.25.5-1.1 is installed"},
					{TestRef: "tst:plat", Comment: "SLES-release is installed"},
				},
			},
		}},
		Tests: []ovalRPMTest{
			{ID: "tst:pkg", Object: ovalObjectRef{Ref: "obj:pkg"}},
			{ID: "tst:plat", Object: ovalObjectRef{Ref: "obj:plat"}},
		},
		Objects: []ovalRPMObject{
			{ID: "obj:pkg", Name: "go1.25"},
			{ID: "obj:plat", Name: "SLES-release"},
		},
	}
}

func TestScanSUSEPatchClass_FlagsInstalledPackageAcrossBothCVEs(t *testing.T) {
	t.Parallel()
	oval := buildSUSEPatchDef("Security update for go1.25 (Important)")
	pkgs := []InstalledPackage{
		{Name: "go1.25", EVR: "0:1.25.5-1.1"},
		{Name: "SLES-release", EVR: "0:15.5-1"},
	}
	got := scanSUSEPatchClass(oval, pkgs)
	if len(got) != 2 {
		t.Fatalf("expected one result per CVE ref (2), got %d: %+v", len(got), got)
	}
	seen := map[string]bool{}
	for _, r := range got {
		seen[r.CVEID] = true
		if r.Severity != "Important" {
			t.Errorf("Severity = %q, want Important (parsed from title)", r.Severity)
		}
		if r.CVSS3 != 8.0 {
			t.Errorf("CVSS3 = %v, want 8.0 (important)", r.CVSS3)
		}
		if len(r.Installed) != 1 || r.Installed[0] != "go1.25" {
			t.Errorf("Installed = %v, want [go1.25] (platform marker excluded)", r.Installed)
		}
	}
	if !seen["CVE-2025-1111"] || !seen["CVE-2025-2222"] {
		t.Errorf("missing expected CVE IDs, got %+v", got)
	}
}

func TestScanSUSEPatchClass_PackageNotInstalledIsSkipped(t *testing.T) {
	t.Parallel()
	oval := buildSUSEPatchDef("Security update for go1.25 (Important)")
	// Neither the package nor the platform marker is installed.
	got := scanSUSEPatchClass(oval, []InstalledPackage{{Name: "unrelated", EVR: "1-1"}})
	if len(got) != 0 {
		t.Errorf("expected no results when nothing installed, got %+v", got)
	}
}

func TestScanSUSEPatchClass_NonPatchClassSkipped(t *testing.T) {
	t.Parallel()
	oval := buildSUSEPatchDef("Security update for go1.25 (Important)")
	oval.Definitions[0].Class = "vulnerability"
	got := scanSUSEPatchClass(oval, []InstalledPackage{{Name: "go1.25", EVR: "0:1.25.5-1.1"}})
	if len(got) != 0 {
		t.Errorf("non-patch-class def must be skipped by the patch scanner, got %+v", got)
	}
}

func TestScanSUSEPatchClass_NoCVERefsSkipped(t *testing.T) {
	t.Parallel()
	oval := buildSUSEPatchDef("Security update for go1.25 (Important)")
	oval.Definitions[0].Metadata.References = nil
	got := scanSUSEPatchClass(oval, []InstalledPackage{{Name: "go1.25", EVR: "0:1.25.5-1.1"}})
	if len(got) != 0 {
		t.Errorf("def with no CVE refs must be skipped, got %+v", got)
	}
}

func TestScanSUSEPatchClass_NoSeverityInTitle(t *testing.T) {
	t.Parallel()
	// Title without a trailing "(Severity)" — severity/cvss default to Unknown/0.
	oval := buildSUSEPatchDef("Recommended update for go1.25")
	got := scanSUSEPatchClass(oval, []InstalledPackage{{Name: "go1.25", EVR: "0:1.25.5-1.1"}})
	if len(got) == 0 {
		t.Fatal("expected results even without a parseable severity")
	}
	if got[0].Severity != "Unknown" || got[0].CVSS3 != 0 {
		t.Errorf("Severity=%q CVSS3=%v, want Unknown/0", got[0].Severity, got[0].CVSS3)
	}
}

// ── collectSUSEPkgs ───────────────────────────────────────────────────────────

func TestCollectSUSEPkgs_ViaTestObjectMap(t *testing.T) {
	t.Parallel()
	testObj := map[string]string{"t1": "o1"}
	objName := map[string]string{"o1": "openssl"}
	c := ovalCriteria{Criterion: []ovalCriterion{{TestRef: "t1"}}}
	out := map[string]bool{}
	collectSUSEPkgs(c, testObj, objName, out)
	if !out["openssl"] || len(out) != 1 {
		t.Errorf("collectSUSEPkgs via map = %v, want {openssl}", out)
	}
}

func TestCollectSUSEPkgs_FallbackCommentRegex(t *testing.T) {
	t.Parallel()
	// No test→object mapping for "tX" — must fall back to parsing the comment.
	c := ovalCriteria{Criterion: []ovalCriterion{
		{TestRef: "tX", Comment: "curl-8.5.0-1.1 is installed"},
	}}
	out := map[string]bool{}
	collectSUSEPkgs(c, map[string]string{}, map[string]string{}, out)
	if !out["curl"] || len(out) != 1 {
		t.Errorf("collectSUSEPkgs fallback = %v, want {curl}", out)
	}
}

func TestCollectSUSEPkgs_NestedCriteria(t *testing.T) {
	t.Parallel()
	c := ovalCriteria{
		Criterion: []ovalCriterion{{TestRef: "t1"}},
		Criteria: []ovalCriteria{
			{Criterion: []ovalCriterion{{TestRef: "tX", Comment: "curl-8.5.0-1.1 is installed"}}},
		},
	}
	testObj := map[string]string{"t1": "o1"}
	objName := map[string]string{"o1": "openssl"}
	out := map[string]bool{}
	collectSUSEPkgs(c, testObj, objName, out)
	if !out["openssl"] || !out["curl"] || len(out) != 2 {
		t.Errorf("collectSUSEPkgs nested = %v, want {openssl, curl}", out)
	}
}

func TestCollectSUSEPkgs_UnmatchedCommentIgnored(t *testing.T) {
	t.Parallel()
	c := ovalCriteria{Criterion: []ovalCriterion{{TestRef: "tX", Comment: "nothing to see here"}}}
	out := map[string]bool{}
	collectSUSEPkgs(c, map[string]string{}, map[string]string{}, out)
	if len(out) != 0 {
		t.Errorf("collectSUSEPkgs should ignore an unmatched comment, got %v", out)
	}
}
