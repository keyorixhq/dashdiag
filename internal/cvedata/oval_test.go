//go:build linux

package cvedata

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// writeFixture writes content to a temp file with the given name and returns
// its path. The name matters for the distro-detection helpers.
func writeFixture(t *testing.T, name, content string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	return p
}

// ── parseCVSS3Attr ───────────────────────────────────────────────────────────

func TestParseCVSS3Attr(t *testing.T) {
	cases := []struct {
		in        string
		wantScore float64
		wantVec   string
	}{
		{"9.1/CVSS:3.1/AV:N/AC:L", 9.1, "CVSS:3.1/AV:N/AC:L"},
		{"7.0/CVSS:3.0/AV:L", 7.0, "CVSS:3.0/AV:L"},
		{"", 0, ""},
		{"novector", 0, ""},     // no "/" separator
		{"x.y/CVSS:3.1", 0, ""}, // unparseable score
	}
	for _, c := range cases {
		score, vec := parseCVSS3Attr(c.in)
		if score != c.wantScore || vec != c.wantVec {
			t.Errorf("parseCVSS3Attr(%q) = (%v,%q), want (%v,%q)", c.in, score, vec, c.wantScore, c.wantVec)
		}
	}
}

// ── cvssLevel ────────────────────────────────────────────────────────────────

func TestCVSSLevel(t *testing.T) {
	cases := []struct {
		score float64
		want  string
	}{
		{9.0, "Critical"}, {9.8, "Critical"},
		{7.0, "High"}, {8.9, "High"},
		{4.0, "Medium"}, {6.9, "Medium"},
		{3.9, "Low"}, {0, "Low"},
	}
	for _, c := range cases {
		if got := cvssLevel(c.score); got != c.want {
			t.Errorf("cvssLevel(%v) = %q, want %q", c.score, got, c.want)
		}
	}
}

// ── sortOVALResults ──────────────────────────────────────────────────────────

func TestSortOVALResults(t *testing.T) {
	r := []OVALCVSSResult{
		{CVEID: "CVE-A", CVSS3: 5.0},
		{CVEID: "CVE-B", CVSS3: 9.1},
		{CVEID: "CVE-C", CVSS3: 7.5},
	}
	sortOVALResults(r)
	if r[0].CVSS3 != 9.1 || r[1].CVSS3 != 7.5 || r[2].CVSS3 != 5.0 {
		t.Errorf("not sorted descending by CVSS: %+v", r)
	}
}

// ── distro detection from path ───────────────────────────────────────────────

func TestDistroDetection(t *testing.T) {
	suse := []string{"/var/lib/dsd/oval/suse.xml", "opensuse-leap.xml", "/x/SLES15.oval"}
	for _, p := range suse {
		if !isSUSEOVAL(p) {
			t.Errorf("isSUSEOVAL(%q) = false, want true", p)
		}
	}
	ubuntu := []string{"ubuntu.oval.xml", "/x/debian13.xml", "canonical-noble.xml"}
	for _, p := range ubuntu {
		if !isUbuntuOVAL(p) {
			t.Errorf("isUbuntuOVAL(%q) = false, want true", p)
		}
	}
	// A RHEL path matches neither.
	if isSUSEOVAL("rhel9.oval.xml") || isUbuntuOVAL("rhel9.oval.xml") {
		t.Error("rhel path should match neither SUSE nor Ubuntu")
	}
}

// ── isSUSEPlatformMarker ─────────────────────────────────────────────────────

func TestIsSUSEPlatformMarker(t *testing.T) {
	for _, m := range []string{"Leap-release", "openSUSE-release", "SLES-release", "leap-RELEASE"} {
		if !isSUSEPlatformMarker(m) {
			t.Errorf("isSUSEPlatformMarker(%q) = false, want true (case-insensitive)", m)
		}
	}
	for _, m := range []string{"go1.25", "openssl", "kernel-default"} {
		if isSUSEPlatformMarker(m) {
			t.Errorf("isSUSEPlatformMarker(%q) = true, want false", m)
		}
	}
}

// ── keys ─────────────────────────────────────────────────────────────────────

func TestKeys(t *testing.T) {
	got := keys(map[string]bool{"a": true, "b": true, "c": true})
	if len(got) != 3 {
		t.Fatalf("keys() returned %d items, want 3: %v", len(got), got)
	}
	set := map[string]bool{}
	for _, k := range got {
		set[k] = true
	}
	for _, want := range []string{"a", "b", "c"} {
		if !set[want] {
			t.Errorf("keys() missing %q", want)
		}
	}
	if keys(map[string]bool{}) == nil || len(keys(map[string]bool{})) != 0 {
		t.Error("keys(empty) should be a non-nil empty slice")
	}
}

// ── IsVulnerable / normaliseEVR ──────────────────────────────────────────────

func TestIsVulnerable(t *testing.T) {
	cases := []struct {
		installed, fixed string
		want             bool
	}{
		{"1.0.0-1", "1.0.0-2", true},  // older -> vulnerable
		{"1.0.0-2", "1.0.0-2", false}, // equal -> safe
		{"1.0.0-3", "1.0.0-2", false}, // newer -> safe
		{"0:1.9-1", "1.9-1", false},   // epoch normalised, equal -> safe
		{"0:1.0-1", "0:1.0-2", true},  // both epoch-zero, older -> vulnerable
	}
	for _, c := range cases {
		if got := IsVulnerable(c.installed, c.fixed); got != c.want {
			t.Errorf("IsVulnerable(%q,%q) = %v, want %v", c.installed, c.fixed, got, c.want)
		}
	}
}

// ── ParseRHELOVAL ────────────────────────────────────────────────────────────

const rhelOVAL = `<?xml version="1.0"?>
<oval_definitions>
  <definitions>
    <definition class="vulnerability">
      <metadata>
        <reference source="CVE" ref_id="CVE-2024-3094"/>
        <advisory>
          <severity>Important</severity>
          <cve cvss3="9.8/CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" impact="critical">CVE-2024-3094</cve>
          <affected>
            <resolution state="Affected">
              <component>xz</component>
              <component>xz-libs</component>
              <component>xz</component>
            </resolution>
          </affected>
        </advisory>
      </metadata>
    </definition>
    <definition class="patch">
      <metadata>
        <reference source="CVE" ref_id="CVE-9999-0000"/>
        <advisory><severity>Low</severity></advisory>
      </metadata>
    </definition>
    <definition class="vulnerability">
      <metadata>
        <reference source="other" ref_id="RHSA-2024:1"/>
        <advisory><severity>Low</severity></advisory>
      </metadata>
    </definition>
  </definitions>
</oval_definitions>`

func TestParseRHELOVAL(t *testing.T) {
	m, err := ParseRHELOVAL(writeFixture(t, "rhel.xml", rhelOVAL))
	if err != nil {
		t.Fatal(err)
	}
	// Only the vulnerability def with a CVE reference is kept; the patch-class
	// def and the no-CVE-ref def are excluded.
	if len(m) != 1 {
		t.Fatalf("got %d records, want 1: %+v", len(m), m)
	}
	rec, ok := m["CVE-2024-3094"]
	if !ok {
		t.Fatal("CVE-2024-3094 missing")
	}
	if rec.CVSS3 != 9.8 {
		t.Errorf("CVSS3 = %v, want 9.8", rec.CVSS3)
	}
	if rec.CVSS3Vector != "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" {
		t.Errorf("vector = %q", rec.CVSS3Vector)
	}
	if rec.Severity != "Important" || rec.State != "Affected" {
		t.Errorf("severity=%q state=%q", rec.Severity, rec.State)
	}
	// Components deduped: xz, xz-libs (the duplicate xz is dropped).
	if len(rec.Components) != 2 {
		t.Errorf("components = %v, want 2 deduped", rec.Components)
	}
}

func TestParseRHELOVAL_Errors(t *testing.T) {
	if _, err := ParseRHELOVAL(filepath.Join(t.TempDir(), "missing.xml")); err == nil {
		t.Error("missing file should error")
	}
	if _, err := ParseRHELOVAL(writeFixture(t, "bad.xml", "<not valid")); err == nil {
		t.Error("malformed XML should error")
	}
}

// TestParseRHELOVAL_EmptyDefinitionsErrors covers internal-cvedata-02-01: XML
// that decodes successfully but yields zero <definition> elements (a
// truncated download that still closes its tags, or a CDN/object-storage XML
// error body served instead of the real feed) must fail loudly, matching
// loadOVAL's guard for the SUSE path and parseUbuntuOVALVersionAware's for
// the Debian/Ubuntu path — not silently read as "scanned successfully, found
// nothing" for the RHEL/Rocky/AlmaLinux/CentOS/Fedora vendor path, which
// ScanOVALPackages dispatches to for that entire distro family.
func TestParseRHELOVAL_EmptyDefinitionsErrors(t *testing.T) {
	t.Parallel()
	empty := `<?xml version="1.0"?><oval_definitions><definitions></definitions></oval_definitions>`
	if _, err := ParseRHELOVAL(writeFixture(t, "empty-defs.xml", empty)); err == nil {
		t.Error("zero-definitions OVAL must error, not read as a clean empty scan")
	}
}

// TestParseRHELOVAL_RejectsOversizedFeed covers internal-cvedata-02-04 /
// read-bounding-06: ParseRHELOVAL must not decode an unbounded amount of XML.
// Go's stdlib bzip2 is decode-only (see the BZ2Suffix test below), so this
// proves the cap via a plain XML file longer than a shrunk cap instead of an
// actual bzip2 bomb — the cap applies to the reader regardless of whether it
// came from bzip2.NewReader or the raw file.
func TestParseRHELOVAL_RejectsOversizedFeed(t *testing.T) {
	withShrunkFeedCap(t, 50) // rhelOVAL is >800 bytes — well past this
	if _, err := ParseRHELOVAL(writeFixture(t, "rhel-big.xml", rhelOVAL)); err == nil {
		t.Error("expected ParseRHELOVAL to reject a feed exceeding the decompressed size cap")
	}
}

// TestParseRHELOVAL_BZ2SuffixUsesBzip2Reader exercises the ".bz2"
// reader-selection branch. Go's stdlib compress/bzip2 is decode-only, so
// real compressed content can't be produced here, but a .bz2-suffixed path
// still exercises bzip2.NewReader construction and the decode-error path.
func TestParseRHELOVAL_BZ2SuffixUsesBzip2Reader(t *testing.T) {
	t.Parallel()
	if _, err := ParseRHELOVAL(writeFixture(t, "rhel.xml.bz2", "not real bzip2 data")); err == nil {
		t.Error("expected a decode error for non-bzip2 content under .xml.bz2")
	}
}

// TestParseRHELOVAL_KeepsHighestScoreAcrossDuplicateDefinitions exercises the
// "CVE appears in multiple definitions -> keep the higher CVSS score" merge
// branch: two separate <definition> elements both reference the same CVE ID
// with different scores.
func TestParseRHELOVAL_KeepsHighestScoreAcrossDuplicateDefinitions(t *testing.T) {
	t.Parallel()
	const feed = `<?xml version="1.0"?>
<oval_definitions>
  <definitions>
    <definition class="vulnerability">
      <metadata>
        <reference source="CVE" ref_id="CVE-2030-8888"/>
        <advisory>
          <severity>Moderate</severity>
          <cve cvss3="5.0/CVSS:3.1/AV:L" impact="moderate">CVE-2030-8888</cve>
          <affected><resolution state="Affected"><component>pkg-a</component></resolution></affected>
        </advisory>
      </metadata>
    </definition>
    <definition class="vulnerability">
      <metadata>
        <reference source="CVE" ref_id="CVE-2030-8888"/>
        <advisory>
          <severity>Critical</severity>
          <cve cvss3="9.5/CVSS:3.1/AV:N" impact="critical">CVE-2030-8888</cve>
          <affected><resolution state="Affected"><component>pkg-b</component></resolution></affected>
        </advisory>
      </metadata>
    </definition>
  </definitions>
</oval_definitions>`
	m, err := ParseRHELOVAL(writeFixture(t, "dup-cve.xml", feed))
	if err != nil {
		t.Fatal(err)
	}
	rec, ok := m["CVE-2030-8888"]
	if !ok {
		t.Fatal("CVE-2030-8888 missing")
	}
	if rec.CVSS3 != 9.5 {
		t.Errorf("CVSS3 = %v, want 9.5 (the higher of the two definitions)", rec.CVSS3)
	}
	if rec.Severity != "Critical" {
		t.Errorf("Severity = %q, want Critical (from the winning higher-score definition)", rec.Severity)
	}
}

// ── ParseUbuntuOVAL ──────────────────────────────────────────────────────────

const ubuntuOVAL = `<?xml version="1.0"?>
<oval_definitions>
  <definitions>
    <definition class="vulnerability">
      <metadata>
        <reference source="CVE" ref_id="CVE-2023-1234"/>
        <advisory>
          <severity>medium</severity>
          <cve priority="high"/>
        </advisory>
      </metadata>
      <criteria>
        <criterion comment="openssl package in noble is affected and may need fixing."/>
        <criteria>
          <criterion comment="curl package in noble is affected and may need fixing."/>
          <criterion comment="unrelated comment that should not match"/>
        </criteria>
      </criteria>
    </definition>
    <definition class="vulnerability">
      <metadata>
        <reference source="CVE" ref_id="CVE-2023-5678"/>
        <advisory><severity>low</severity></advisory>
      </metadata>
      <criteria>
        <criterion comment="nothing affected here"/>
      </criteria>
    </definition>
  </definitions>
</oval_definitions>`

func TestParseUbuntuOVAL(t *testing.T) {
	m, err := ParseUbuntuOVAL(writeFixture(t, "ubuntu.xml", ubuntuOVAL))
	if err != nil {
		t.Fatal(err)
	}
	// CVE-2023-5678 has no affected packages -> excluded.
	if len(m) != 1 {
		t.Fatalf("got %d records, want 1: %+v", len(m), m)
	}
	rec, ok := m["CVE-2023-1234"]
	if !ok {
		t.Fatal("CVE-2023-1234 missing")
	}
	// <cve priority="high"> overrides the medium <severity>.
	if rec.Severity != "High" {
		t.Errorf("severity = %q, want High (priority overrides severity)", rec.Severity)
	}
	if rec.CVSS3 != 8.0 {
		t.Errorf("CVSS3 = %v, want 8.0 (high)", rec.CVSS3)
	}
	// Packages extracted from both direct and nested criterion comments.
	if len(rec.Components) != 2 {
		t.Fatalf("components = %v, want [openssl curl]", rec.Components)
	}
	wantPkg := map[string]bool{"openssl": true, "curl": true}
	for _, c := range rec.Components {
		if !wantPkg[c] {
			t.Errorf("unexpected component %q", c)
		}
	}
}

// Regression: a vulnerability def with no severity and no <cve priority> must
// not panic on priority[:1]. (Found while writing these tests.)
func TestParseUbuntuOVAL_EmptyPriorityNoPanic(t *testing.T) {
	const x = `<oval_definitions><definitions>
      <definition class="vulnerability">
        <metadata>
          <reference source="CVE" ref_id="CVE-2024-0001"/>
          <advisory></advisory>
        </metadata>
        <criteria><criterion comment="bash package in noble is affected and may need fixing."/></criteria>
      </definition>
    </definitions></oval_definitions>`
	m, err := ParseUbuntuOVAL(writeFixture(t, "empty-prio.xml", x)) // must not panic
	if err != nil {
		t.Fatal(err)
	}
	if rec, ok := m["CVE-2024-0001"]; !ok || rec.Severity != "" {
		t.Errorf("want record with empty severity, got %+v (ok=%v)", rec, ok)
	}
}

func TestParseUbuntuOVAL_Errors(t *testing.T) {
	if _, err := ParseUbuntuOVAL(filepath.Join(t.TempDir(), "missing.xml")); err == nil {
		t.Error("missing file should error")
	}
	if _, err := ParseUbuntuOVAL(writeFixture(t, "bad.xml", "<nope")); err == nil {
		t.Error("malformed XML should error")
	}
}

// TestParseUbuntuOVAL_EmptyDefinitionsErrors covers internal-cvedata-01-01:
// XML that decodes successfully but yields zero <definition> elements (a
// truncated download that still closes its tags, or a CDN/object-storage XML
// error body served instead of the real feed) must fail loudly, matching
// loadOVAL's guard for the SUSE/RHEL path — not silently read as "scanned
// successfully, found nothing".
func TestParseUbuntuOVAL_EmptyDefinitionsErrors(t *testing.T) {
	t.Parallel()
	empty := `<?xml version="1.0"?><oval_definitions><definitions></definitions></oval_definitions>`
	if _, err := ParseUbuntuOVAL(writeFixture(t, "empty-defs.xml", empty)); err == nil {
		t.Error("zero-definitions OVAL must error, not read as a clean empty scan")
	}
}

// TestParseUbuntuOVALVersionAware_EmptyDefinitionsErrors is the same guard on
// the version-aware parser used by the production ScanUbuntuOVALPackages path.
func TestParseUbuntuOVALVersionAware_EmptyDefinitionsErrors(t *testing.T) {
	t.Parallel()
	empty := `<?xml version="1.0"?><oval_definitions><definitions></definitions></oval_definitions>`
	if _, err := parseUbuntuOVALVersionAware(strings.NewReader(empty)); err == nil {
		t.Error("zero-definitions OVAL must error, not read as a clean empty scan")
	}
}

// TestParseUbuntuOVAL_RejectsOversizedFeed covers internal-cvedata-01-04 /
// read-bounding-07: same cap as ParseRHELOVAL, proven the same way (a plain
// XML file longer than a shrunk cap — see that test's comment for why bzip2
// isn't used directly here).
func TestParseUbuntuOVAL_RejectsOversizedFeed(t *testing.T) {
	withShrunkFeedCap(t, 50)
	if _, err := ParseUbuntuOVAL(writeFixture(t, "ubuntu-big.xml", ubuntuOVAL)); err == nil {
		t.Error("expected ParseUbuntuOVAL to reject a feed exceeding the decompressed size cap")
	}
}

// TestParseUbuntuOVAL_BZ2SuffixUsesBzip2Reader exercises the ".bz2"
// reader-selection branch. Go's stdlib compress/bzip2 is decode-only, so
// real compressed content can't be produced here, but a .bz2-suffixed path
// still exercises bzip2.NewReader construction and the decode-error path.
func TestParseUbuntuOVAL_BZ2SuffixUsesBzip2Reader(t *testing.T) {
	t.Parallel()
	if _, err := ParseUbuntuOVAL(writeFixture(t, "ubuntu.xml.bz2", "not real bzip2 data")); err == nil {
		t.Error("expected a decode error for non-bzip2 content under .xml.bz2")
	}
}

// TestParseUbuntuOVAL_SkipsNonVulnerabilityClassAndMissingCVERef confirms two
// distinct skip branches: a definition whose class isn't "vulnerability", and
// a vulnerability definition that carries no CVE reference at all (e.g. only
// a Launchpad bug reference) — neither should produce a result record.
func TestParseUbuntuOVAL_SkipsNonVulnerabilityClassAndMissingCVERef(t *testing.T) {
	t.Parallel()
	const feed = `<?xml version="1.0"?>
<oval_definitions>
  <definitions>
    <definition class="patch">
      <metadata>
        <reference source="CVE" ref_id="CVE-2030-1111"/>
        <advisory><severity>high</severity></advisory>
      </metadata>
      <criteria><criterion comment="openssl package in noble is affected and may need fixing."/></criteria>
    </definition>
    <definition class="vulnerability">
      <metadata>
        <reference source="LP" ref_id="1234567"/>
        <advisory><severity>high</severity></advisory>
      </metadata>
      <criteria><criterion comment="curl package in noble is affected and may need fixing."/></criteria>
    </definition>
  </definitions>
</oval_definitions>`
	m, err := ParseUbuntuOVAL(writeFixture(t, "skip-cases.xml", feed))
	if err != nil {
		t.Fatal(err)
	}
	if len(m) != 0 {
		t.Errorf("got %d records, want 0 (non-vulnerability class and missing CVE ref both skipped): %+v", len(m), m)
	}
}

// ── loadOVAL + CheckCVEFromOVAL (SUSE-shaped) ────────────────────────────────

const suseOVAL = `<?xml version="1.0"?>
<oval_definitions>
  <definitions>
    <definition id="oval:def:1" class="patch">
      <metadata>
        <title>Security update for go1.25 (Important)</title>
        <reference source="CVE" ref_id="CVE-2025-0001"/>
        <advisory><severity>important</severity></advisory>
      </metadata>
      <criteria>
        <criterion test_ref="oval:tst:1" comment="go1.25-1.25.5-1.1 is installed"/>
      </criteria>
    </definition>
  </definitions>
  <tests>
    <rpminfo_test id="oval:tst:1"><object object_ref="oval:obj:1"/><state state_ref="oval:ste:1"/></rpminfo_test>
  </tests>
  <objects>
    <rpminfo_object id="oval:obj:1"><name>go1.25</name></rpminfo_object>
  </objects>
  <states>
    <rpminfo_state id="oval:ste:1"><evr operation="less than">0:1.25.5-1.1</evr></rpminfo_state>
  </states>
</oval_definitions>`

func TestLoadOVAL(t *testing.T) {
	oval, err := loadOVAL(writeFixture(t, "suse.xml", suseOVAL))
	if err != nil {
		t.Fatal(err)
	}
	if len(oval.Definitions) != 1 || len(oval.Tests) != 1 ||
		len(oval.Objects) != 1 || len(oval.States) != 1 {
		t.Fatalf("parsed counts wrong: defs=%d tests=%d objs=%d states=%d",
			len(oval.Definitions), len(oval.Tests), len(oval.Objects), len(oval.States))
	}
	if oval.Objects[0].Name != "go1.25" {
		t.Errorf("object name = %q", oval.Objects[0].Name)
	}
	if oval.Tests[0].ObjectRef() != "oval:obj:1" || oval.Tests[0].StateRef() != "oval:ste:1" {
		t.Errorf("test refs wrong: obj=%q state=%q", oval.Tests[0].ObjectRef(), oval.Tests[0].StateRef())
	}
}

func TestLoadOVAL_Errors(t *testing.T) {
	if _, err := loadOVAL(filepath.Join(t.TempDir(), "missing.xml")); err == nil {
		t.Error("missing file should error")
	}
	if _, err := loadOVAL(writeFixture(t, "bad.xml", "<broken")); err == nil {
		t.Error("malformed XML should error")
	}
}

// TestLoadOVAL_RejectsOversizedFeed covers internal-cvedata-01-03 /
// read-bounding-05: same cap as ParseRHELOVAL/ParseUbuntuOVAL, proven the
// same way (see ParseRHELOVAL_RejectsOversizedFeed's comment for why bzip2
// isn't used directly here).
func TestLoadOVAL_RejectsOversizedFeed(t *testing.T) {
	withShrunkFeedCap(t, 50)
	if _, err := loadOVAL(writeFixture(t, "suse-big.xml", suseOVAL)); err == nil {
		t.Error("expected loadOVAL to reject a feed exceeding the decompressed size cap")
	}
}

// TestLoadOVAL_BZ2SuffixUsesBzip2Reader exercises the ".bz2" reader-selection
// branch. Go's stdlib compress/bzip2 is decode-only, so real compressed
// content can't be produced here, but a .bz2-suffixed path still exercises
// bzip2.NewReader construction and the subsequent decode-error path.
func TestLoadOVAL_BZ2SuffixUsesBzip2Reader(t *testing.T) {
	t.Parallel()
	if _, err := loadOVAL(writeFixture(t, "feed.xml.bz2", "not real bzip2 data")); err == nil {
		t.Error("expected a decode error for non-bzip2 content under .xml.bz2")
	}
}

// CheckCVEFromOVAL: the not-found path is fully deterministic (no rpm query is
// reached when the CVE is absent from the OVAL file).
func TestCheckCVEFromOVAL_NotFound(t *testing.T) {
	path := writeFixture(t, "suse.xml", suseOVAL)
	res, err := CheckCVEFromOVAL(context.Background(), path, "CVE-1999-9999")
	if err != nil {
		t.Fatal(err)
	}
	if res.Found {
		t.Errorf("CVE-1999-9999 should not be found, got %+v", res)
	}
	if res.CVE != "CVE-1999-9999" {
		t.Errorf("CVE field = %q, want normalised input", res.CVE)
	}
}

func TestCheckCVEFromOVAL_LoadError(t *testing.T) {
	if _, err := CheckCVEFromOVAL(context.Background(), filepath.Join(t.TempDir(), "x.xml"), "CVE-1-1"); err == nil {
		t.Error("missing OVAL file should error")
	}
}

// ── collectMatches (pure tree walk, no I/O) ──────────────────────────────────

func TestCollectMatches(t *testing.T) {
	tests := map[string]*ovalRPMTest{
		"t1": {ID: "t1", Object: ovalObjectRef{Ref: "o1"}, State: ovalStateRef{Ref: "s1"}},
		"t2": {ID: "t2", Object: ovalObjectRef{Ref: "o2"}, State: ovalStateRef{Ref: "s2"}},
		"t3": {ID: "t3", Object: ovalObjectRef{Ref: "oX"}, State: ovalStateRef{Ref: "sX"}}, // dangling obj
		"t4": {ID: "t4", Object: ovalObjectRef{Ref: "o1"}, State: ovalStateRef{Ref: "sX"}}, // dangling state
		"t5": {ID: "t5", Object: ovalObjectRef{Ref: "o3"}, State: ovalStateRef{Ref: "s1"}}, // pkg not installed
	}
	objects := map[string]*ovalRPMObject{
		"o1": {ID: "o1", Name: "vulnpkg"},
		"o2": {ID: "o2", Name: "safepkg"},
		"o3": {ID: "o3", Name: "notinstalledpkg"},
	}
	states := map[string]*ovalRPMState{
		"s1": {ID: "s1", EVR: ovalEVR{Value: "0:2.0-1"}},
		"s2": {ID: "s2", EVR: ovalEVR{Value: "0:2.0-1"}},
	}
	installed := map[string]string{
		"vulnpkg": "0:1.0-1", // older than fixed 2.0-1 -> vulnerable
		"safepkg": "0:2.0-1", // equal to fixed -> not vulnerable
		// "otherpkg" not installed
		// "notinstalledpkg" also not installed -> exercises the "present" guard
	}
	// Nested criteria: outer criterion (vulnpkg) + a sub-criteria with safepkg
	// and criteria whose tests have a dangling object ref (t3), dangling state
	// ref (t4), and a not-installed package (t5) — all should be skipped.
	crit := ovalCriteria{
		Criterion: []ovalCriterion{
			{TestRef: "t1"}, {TestRef: "t3"}, {TestRef: "missing"},
			{TestRef: "t4"}, {TestRef: "t5"},
		},
		Criteria: []ovalCriteria{
			{Criterion: []ovalCriterion{{TestRef: "t2"}}},
		},
	}

	res := &OVALResult{}
	collectMatches(crit, tests, objects, states, installed, res)

	if len(res.Packages) != 1 {
		t.Fatalf("want 1 vulnerable package, got %d: %+v", len(res.Packages), res.Packages)
	}
	m := res.Packages[0]
	if m.Name != "vulnpkg" || m.Installed != "0:1.0-1" || m.FixedIn != "0:2.0-1" {
		t.Errorf("match = %+v, want vulnpkg 1.0-1 fixed 2.0-1", m)
	}
}

func TestLoadOVAL_EmptyDefinitions(t *testing.T) {
	dir := t.TempDir()
	// Well-formed XML but no <definition> entries — must error, not silently
	// return an empty feed that makes every CVE come back "not vulnerable".
	p := filepath.Join(dir, "empty.xml")
	if err := os.WriteFile(p, []byte(`<?xml version="1.0"?><oval_definitions></oval_definitions>`), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := loadOVAL(p); err == nil {
		t.Error("loadOVAL on a 0-definition file should error, got nil")
	}
}
