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

// TestScanSUSEVulnClass_KernelEqualsLeafStillCaught guards the adversarial
// finding: SUSE kernel CVEs carry an exact-version "equals" leaf ALONGSIDE the
// "less than fixed" leaf (the livepatch/flavor pattern). dsd matches only the
// "less than" leaf, but every real kernel-default vuln def on Leap 16.0 has one,
// so the kernel is still flagged — no equals-only false negative.
func TestScanSUSEVulnClass_KernelEqualsLeafStillCaught(t *testing.T) {
	oval := &ovalDefinitions{
		Definitions: []ovalDefinition{{
			ID: "oval:test:def:k", Class: "vulnerability",
			Metadata: ovalMetadata{References: []ovalReference{{Source: "CVE", RefID: "Mitre CVE-2025-7777"}}},
			Criteria: ovalCriteria{Criteria: []ovalCriteria{{Criterion: []ovalCriterion{
				{TestRef: "tst:keq"}, // exact-version equals leaf (dsd ignores)
				{TestRef: "tst:klt"}, // less-than fix leaf (dsd matches)
			}}}},
		}},
		Tests: []ovalRPMTest{
			{ID: "tst:keq", Object: ovalObjectRef{Ref: "obj:k"}, State: ovalStateRef{Ref: "ste:keq"}},
			{ID: "tst:klt", Object: ovalObjectRef{Ref: "obj:k"}, State: ovalStateRef{Ref: "ste:klt"}},
		},
		Objects: []ovalRPMObject{{ID: "obj:k", Name: "kernel-default"}},
		States: []ovalRPMState{
			{ID: "ste:keq", EVR: ovalEVR{Value: "6.4.0-150600.1", Operation: "equals"}},
			{ID: "ste:klt", EVR: ovalEVR{Value: "6.4.0-150600.9", Operation: "less than"}},
		},
	}
	pkgs := []InstalledPackage{{Name: "kernel-default", EVR: "0:6.4.0-150600.3"}}
	got := scanSUSEVulnClass(oval, pkgs)
	if len(got) != 1 || got[0].CVEID != "CVE-2025-7777" {
		t.Fatalf("kernel below fixed must be flagged via the less-than leaf, got %+v", got)
	}
}

func TestDedupOVALByCVE(t *testing.T) {
	in := []OVALCVSSResult{
		{CVEID: "CVE-1", CVSS3: 9.0},
		{CVEID: "CVE-2", CVSS3: 7.0},
		{CVEID: "CVE-1", CVSS3: 5.0}, // dup from the other class path → dropped
	}
	got := dedupOVALByCVE(in)
	if len(got) != 2 || got[0].CVEID != "CVE-1" || got[1].CVEID != "CVE-2" {
		t.Errorf("dedupOVALByCVE = %+v, want [CVE-1 CVE-2]", got)
	}
}

// TestDedupOVALByCVE_ShortInputReturnsUnchanged exercises the "len(in) < 2"
// early return: 0 and 1 element inputs can't contain a duplicate, so the
// function returns them as-is without allocating the seen-map/output slice.
func TestDedupOVALByCVE_ShortInputReturnsUnchanged(t *testing.T) {
	t.Parallel()
	if got := dedupOVALByCVE(nil); got != nil {
		t.Errorf("dedupOVALByCVE(nil) = %+v, want nil", got)
	}
	one := []OVALCVSSResult{{CVEID: "CVE-1", CVSS3: 9.0}}
	got := dedupOVALByCVE(one)
	if len(got) != 1 || got[0].CVEID != "CVE-1" {
		t.Errorf("dedupOVALByCVE(single) = %+v, want unchanged [CVE-1]", got)
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

// TestScanSUSEVulnClass_SkipsNonVulnerabilityClass confirms definitions whose
// class isn't "vulnerability" (e.g. "patch", handled by the sibling
// presence-based scanner) are skipped rather than double-counted.
func TestScanSUSEVulnClass_SkipsNonVulnerabilityClass(t *testing.T) {
	t.Parallel()
	oval := buildSUSEVulnDef("1.0-2")
	oval.Definitions[0].Class = "patch"
	pkgs := []InstalledPackage{{Name: "foo", EVR: "0:1.0-1"}}
	if got := scanSUSEVulnClass(oval, pkgs); len(got) != 0 {
		t.Errorf("non-vulnerability class must be skipped, got %+v", got)
	}
}

// TestScanSUSEVulnClass_SkipsDefinitionWithNoCVERefs confirms a definition
// carrying no CVE reference (e.g. only a bugzilla/vendor reference) is
// skipped rather than emitting a result with an empty CVE ID.
func TestScanSUSEVulnClass_SkipsDefinitionWithNoCVERefs(t *testing.T) {
	t.Parallel()
	oval := buildSUSEVulnDef("1.0-2")
	oval.Definitions[0].Metadata.References = []ovalReference{
		{Source: "BUGZILLA", RefID: "12345"},
	}
	pkgs := []InstalledPackage{{Name: "foo", EVR: "0:1.0-1"}}
	if got := scanSUSEVulnClass(oval, pkgs); len(got) != 0 {
		t.Errorf("definition with no CVE refs must be skipped, got %+v", got)
	}
}

// TestCollectSUSEVulnMatches_PlatformMarkerSkippedEvenBelowFixedVersion
// guards against flagging the SUSE platform-version sentinel package (e.g.
// "openSUSE-release") as a vulnerable component even when its test happens to
// carry a "less than" operation below its installed version — the marker
// check (isSUSEPlatformMarker) must still exclude it.
func TestCollectSUSEVulnMatches_PlatformMarkerSkippedEvenBelowFixedVersion(t *testing.T) {
	t.Parallel()
	tests := map[string]susePkgFixTest{
		"tst:marker": {pkg: "openSUSE-release", fixed: ovalEVR{Value: "0:17.0-1", Operation: "less than"}},
	}
	installed := map[string]string{"openSUSE-release": "0:16.0-1"}
	c := ovalCriteria{Criterion: []ovalCriterion{{TestRef: "tst:marker"}}}
	out := map[string]string{}
	collectSUSEVulnMatches(c, tests, installed, out)
	if len(out) != 0 {
		t.Errorf("platform marker must never be flagged, got %+v", out)
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

// TestSniffOVALVendor_MissingFileReturnsEmpty exercises the os.Open error
// branch: a nonexistent path can't be sniffed, so the vendor is
// inconclusive ("") rather than the function erroring out — callers fall
// back to filename-based detection in that case.
func TestSniffOVALVendor_MissingFileReturnsEmpty(t *testing.T) {
	t.Parallel()
	if v := sniffOVALVendor(filepath.Join(t.TempDir(), "missing.xml")); v != "" {
		t.Errorf("sniffOVALVendor(missing) = %q, want empty", v)
	}
}

// TestSniffOVALVendor_BZ2SuffixUsesBzip2Reader exercises the ".bz2" reader-
// selection branch. Go's stdlib compress/bzip2 is decode-only, so real
// compressed content can't be generated here, but a .bz2-suffixed path still
// exercises the bzip2.NewReader construction + the head read that follows —
// on non-bzip2 bytes it degrades to a head with no vendor markers, i.e. "".
func TestSniffOVALVendor_BZ2SuffixUsesBzip2Reader(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	path := filepath.Join(dir, "feed.xml.bz2")
	if err := os.WriteFile(path, []byte("not real bzip2 data"), 0o600); err != nil {
		t.Fatal(err)
	}
	if v := sniffOVALVendor(path); v != "" {
		t.Errorf("sniffOVALVendor(non-bzip2 .bz2 content) = %q, want empty (no vendor marker found)", v)
	}
}
