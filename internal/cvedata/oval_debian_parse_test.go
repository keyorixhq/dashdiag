//go:build linux

package cvedata

import (
	"strings"
	"testing"
)

// TestParseUbuntuOVALVersionAware_NonVulnerabilityClass exercises the
// "def.Class != vulnerability → continue" branch (oval_debian.go:72).
// A definition with class="patch" must be silently skipped; the result
// slice stays empty.
func TestParseUbuntuOVALVersionAware_NonVulnerabilityClass(t *testing.T) {
	t.Parallel()
	const feed = `<?xml version="1.0"?>
<oval_definitions>
  <definitions>
    <definition class="patch">
      <metadata>
        <reference source="CVE" ref_id="CVE-2030-1111"/>
        <advisory><severity>high</severity></advisory>
      </metadata>
      <criteria>
        <criterion comment="bash DPKG is earlier than 5.0"/>
      </criteria>
    </definition>
  </definitions>
</oval_definitions>`
	entries, err := parseUbuntuOVALVersionAware(strings.NewReader(feed))
	if err != nil {
		t.Fatalf("parseUbuntuOVALVersionAware: %v", err)
	}
	if len(entries) != 0 {
		t.Errorf("got %d entries, want 0 (non-vulnerability class must be skipped)", len(entries))
	}
}

// TestParseUbuntuOVALVersionAware_NoCVERef exercises the "cveID == "" →
// continue" branch (oval_debian.go:83). A vulnerability-class definition
// with no CVE reference must be skipped.
func TestParseUbuntuOVALVersionAware_NoCVERef(t *testing.T) {
	t.Parallel()
	const feed = `<?xml version="1.0"?>
<oval_definitions>
  <definitions>
    <definition class="vulnerability">
      <metadata>
        <reference source="OTHER" ref_id="OTHER-2030-1111"/>
        <advisory><severity>high</severity></advisory>
      </metadata>
      <criteria>
        <criterion comment="bash DPKG is earlier than 5.0"/>
      </criteria>
    </definition>
  </definitions>
</oval_definitions>`
	entries, err := parseUbuntuOVALVersionAware(strings.NewReader(feed))
	if err != nil {
		t.Fatalf("parseUbuntuOVALVersionAware: %v", err)
	}
	if len(entries) != 0 {
		t.Errorf("got %d entries, want 0 (no CVE reference must be skipped)", len(entries))
	}
}

// TestParseUbuntuOVALVersionAware_CVEPriorityOverride exercises the per-CVE
// priority override loop (oval_debian.go:88-91). When a <cve priority="…">
// element is present inside the advisory, it must override the advisory-level
// severity for the CVSS lookup.
func TestParseUbuntuOVALVersionAware_CVEPriorityOverride(t *testing.T) {
	t.Parallel()
	const feed = `<?xml version="1.0"?>
<oval_definitions>
  <definitions>
    <definition class="vulnerability">
      <metadata>
        <reference source="CVE" ref_id="CVE-2030-2222"/>
        <advisory>
          <severity>low</severity>
          <cve priority="critical"/>
        </advisory>
      </metadata>
      <criteria>
        <criterion comment="bash DPKG is earlier than 5.0"/>
      </criteria>
    </definition>
  </definitions>
</oval_definitions>`
	entries, err := parseUbuntuOVALVersionAware(strings.NewReader(feed))
	if err != nil {
		t.Fatalf("parseUbuntuOVALVersionAware: %v", err)
	}
	if len(entries) != 1 {
		t.Fatalf("got %d entries, want 1", len(entries))
	}
	if entries[0].severity != "Critical" {
		t.Errorf("severity = %q, want %q (cve priority= must override advisory severity)", entries[0].severity, "Critical")
	}
	wantCVSS := ubuntuPriorityToCVSS["critical"]
	if entries[0].cvss != wantCVSS {
		t.Errorf("cvss = %v, want %v", entries[0].cvss, wantCVSS)
	}
}

// TestParseUbuntuOVALVersionAware_DuplicateDPKGCriterionPreservesVersion
// exercises the "already have a version for this package → return early"
// branch (oval_debian.go:107-109). When the same package appears in two
// "DPKG is earlier than" criteria inside one definition, the first version
// must win and the second must be ignored.
func TestParseUbuntuOVALVersionAware_DuplicateDPKGCriterionPreservesVersion(t *testing.T) {
	t.Parallel()
	const feed = `<?xml version="1.0"?>
<oval_definitions>
  <definitions>
    <definition class="vulnerability">
      <metadata>
        <reference source="CVE" ref_id="CVE-2030-3333"/>
        <advisory><severity>high</severity></advisory>
      </metadata>
      <criteria>
        <criterion comment="bash DPKG is earlier than 5.0"/>
        <criterion comment="bash DPKG is earlier than 9.0"/>
      </criteria>
    </definition>
  </definitions>
</oval_definitions>`
	entries, err := parseUbuntuOVALVersionAware(strings.NewReader(feed))
	if err != nil {
		t.Fatalf("parseUbuntuOVALVersionAware: %v", err)
	}
	if len(entries) != 1 {
		t.Fatalf("got %d entries, want 1", len(entries))
	}
	if len(entries[0].pkgs) != 1 {
		t.Fatalf("pkgs length = %d, want 1 (duplicate name must be deduplicated)", len(entries[0].pkgs))
	}
	if entries[0].pkgs[0].fixedIn != "5.0" {
		t.Errorf("fixedIn = %q, want %q (first version must win)", entries[0].pkgs[0].fixedIn, "5.0")
	}
}

// TestParseUbuntuOVALVersionAware_EmptyPkgMap exercises the
// "len(pkgMap) == 0 → continue" branch (oval_debian.go:129). A definition
// with class="vulnerability" + a valid CVE reference but no criterion
// comments that match either regex must produce no entries.
func TestParseUbuntuOVALVersionAware_EmptyPkgMap(t *testing.T) {
	t.Parallel()
	const feed = `<?xml version="1.0"?>
<oval_definitions>
  <definitions>
    <definition class="vulnerability">
      <metadata>
        <reference source="CVE" ref_id="CVE-2030-4444"/>
        <advisory><severity>high</severity></advisory>
      </metadata>
      <criteria>
        <criterion comment="this comment matches neither regex"/>
      </criteria>
    </definition>
  </definitions>
</oval_definitions>`
	entries, err := parseUbuntuOVALVersionAware(strings.NewReader(feed))
	if err != nil {
		t.Fatalf("parseUbuntuOVALVersionAware: %v", err)
	}
	if len(entries) != 0 {
		t.Errorf("got %d entries, want 0 (no matching criterion → empty pkgMap → skip)", len(entries))
	}
}
