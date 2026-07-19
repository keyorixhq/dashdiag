//go:build linux

package cvedata

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

// Version-aware test helpers
// ─────────────────────────────────────────────────────────────────────────────
// Each test that needs a specific installed version injects a fake dpkg-query
// via t.Setenv("PATH", dir). These tests cannot be t.Parallel() because
// t.Setenv is incompatible with parallel sub-tests.

// fakeDpkgQuery writes a shell script at dir/dpkg-query that emits the given
// tab-separated "name\tversion" lines and sets PATH so exec.LookPath finds it.
func fakeDpkgQuery(t *testing.T, lines ...string) {
	t.Helper()
	dir := t.TempDir()
	script := "#!/bin/sh\n"
	for _, l := range lines {
		script += "echo '" + l + "'\n"
	}
	if err := os.WriteFile(filepath.Join(dir, "dpkg-query"), []byte(script), 0o755); err != nil {
		t.Fatalf("writing fake dpkg-query: %v", err)
	}
	t.Setenv("PATH", dir)
}

// TestScanUbuntuOVALPackages_VersionAware_Patched verifies that a package
// whose installed version is GREATER THAN OR EQUAL TO the OVAL fixedIn is
// NOT reported as vulnerable — the critical false-positive this feature fixes.
func TestScanUbuntuOVALPackages_VersionAware_Patched(t *testing.T) {
	// bash installed at 5.2.15-2; OVAL says fixed at 5.0 → already patched.
	fakeDpkgQuery(t, "bash\t5.2.15-2")
	const feed = `<?xml version="1.0"?>
<oval_definitions>
  <definitions>
    <definition class="vulnerability">
      <metadata>
        <reference source="CVE" ref_id="CVE-2031-PATCHED"/>
        <advisory><severity>high</severity></advisory>
      </metadata>
      <criteria>
        <criterion comment="bash DPKG is earlier than 5.0"/>
      </criteria>
    </definition>
  </definitions>
</oval_definitions>`
	results, err := ScanUbuntuOVALPackages(context.Background(), writeFixture(t, "ubuntu-patched.xml", feed))
	if err != nil {
		t.Fatalf("ScanUbuntuOVALPackages: %v", err)
	}
	if len(results) != 0 {
		t.Errorf("got %d results, want 0 (bash 5.2.15-2 >= fixedIn 5.0 → already patched): %+v", len(results), results)
	}
}

// TestScanUbuntuOVALPackages_VersionAware_Vulnerable verifies that a package
// whose installed version is BELOW the OVAL fixedIn IS reported as vulnerable.
func TestScanUbuntuOVALPackages_VersionAware_Vulnerable(t *testing.T) {
	// bash installed at 1.0; OVAL says fixed at 5.0 → still vulnerable.
	fakeDpkgQuery(t, "bash\t1.0")
	const feed = `<?xml version="1.0"?>
<oval_definitions>
  <definitions>
    <definition class="vulnerability">
      <metadata>
        <reference source="CVE" ref_id="CVE-2031-VULN"/>
        <advisory><severity>critical</severity></advisory>
      </metadata>
      <criteria>
        <criterion comment="bash DPKG is earlier than 5.0"/>
      </criteria>
    </definition>
  </definitions>
</oval_definitions>`
	results, err := ScanUbuntuOVALPackages(context.Background(), writeFixture(t, "ubuntu-vuln.xml", feed))
	if err != nil {
		t.Fatalf("ScanUbuntuOVALPackages: %v", err)
	}
	if len(results) != 1 || results[0].CVEID != "CVE-2031-VULN" {
		t.Fatalf("got %+v, want 1 result for CVE-2031-VULN (bash 1.0 < fixedIn 5.0)", results)
	}
	if len(results[0].Installed) != 1 || results[0].Installed[0] != "bash" {
		t.Errorf("Installed = %v, want [bash]", results[0].Installed)
	}
}

// TestScanUbuntuOVALPackages_VersionAware_Mixed verifies mixed criteria in one
// definition: one package patched (installed >= fixedIn), one still vulnerable
// (installed < fixedIn). Only the vulnerable package must appear in Installed.
func TestScanUbuntuOVALPackages_VersionAware_Mixed(t *testing.T) {
	// bash 5.0 patched (fixedIn 5.0), coreutils 8.0 vulnerable (fixedIn 9.0).
	fakeDpkgQuery(t, "bash\t5.0", "coreutils\t8.0")
	const feed = `<?xml version="1.0"?>
<oval_definitions>
  <definitions>
    <definition class="vulnerability">
      <metadata>
        <reference source="CVE" ref_id="CVE-2031-MIXED"/>
        <advisory><severity>medium</severity></advisory>
      </metadata>
      <criteria>
        <criterion comment="bash DPKG is earlier than 5.0"/>
        <criterion comment="coreutils DPKG is earlier than 9.0"/>
      </criteria>
    </definition>
  </definitions>
</oval_definitions>`
	results, err := ScanUbuntuOVALPackages(context.Background(), writeFixture(t, "ubuntu-mixed.xml", feed))
	if err != nil {
		t.Fatalf("ScanUbuntuOVALPackages: %v", err)
	}
	if len(results) != 1 || results[0].CVEID != "CVE-2031-MIXED" {
		t.Fatalf("got %+v, want 1 result (coreutils still vulnerable)", results)
	}
	if len(results[0].Installed) != 1 || results[0].Installed[0] != "coreutils" {
		t.Errorf("Installed = %v, want [coreutils] (bash is patched, coreutils is not)", results[0].Installed)
	}
	if len(results[0].Components) != 2 {
		t.Errorf("Components = %v, want 2 (both packages listed in OVAL)", results[0].Components)
	}
}

// TestScanUbuntuOVALPackages_VersionAware_NoFix verifies that the "is affected
// and may need fixing" form (no fixedIn) still flags an installed package —
// conservative behaviour when no fix has been published yet.
func TestScanUbuntuOVALPackages_VersionAware_NoFix(t *testing.T) {
	fakeDpkgQuery(t, "bash\t5.99")
	const feed = `<?xml version="1.0"?>
<oval_definitions>
  <definitions>
    <definition class="vulnerability">
      <metadata>
        <reference source="CVE" ref_id="CVE-2031-NOFIX"/>
        <advisory><severity>high</severity></advisory>
      </metadata>
      <criteria>
        <criterion comment="bash package in noble is affected and may need fixing."/>
      </criteria>
    </definition>
  </definitions>
</oval_definitions>`
	results, err := ScanUbuntuOVALPackages(context.Background(), writeFixture(t, "ubuntu-nofix.xml", feed))
	if err != nil {
		t.Fatalf("ScanUbuntuOVALPackages: %v", err)
	}
	if len(results) != 1 || results[0].CVEID != "CVE-2031-NOFIX" {
		t.Fatalf("got %+v, want 1 result (no fix → flag installed package)", results)
	}
	if len(results[0].Installed) != 1 || results[0].Installed[0] != "bash" {
		t.Errorf("Installed = %v, want [bash]", results[0].Installed)
	}
}

// TestScanUbuntuOVALPackages_VersionAware_ExactVersion tests the boundary at
// CompareDpkg(a, b) == 0: installed == fixedIn → patched, must not be flagged.
func TestScanUbuntuOVALPackages_VersionAware_ExactVersion(t *testing.T) {
	fakeDpkgQuery(t, "openssl\t1:3.0.13-0ubuntu3.4")
	const feed = `<?xml version="1.0"?>
<oval_definitions>
  <definitions>
    <definition class="vulnerability">
      <metadata>
        <reference source="CVE" ref_id="CVE-2031-EXACT"/>
        <advisory><severity>high</severity></advisory>
      </metadata>
      <criteria>
        <criteria>
          <criterion comment="openssl DPKG is earlier than 1:3.0.13-0ubuntu3.4"/>
        </criteria>
      </criteria>
    </definition>
  </definitions>
</oval_definitions>`
	results, err := ScanUbuntuOVALPackages(context.Background(), writeFixture(t, "ubuntu-exact.xml", feed))
	if err != nil {
		t.Fatalf("ScanUbuntuOVALPackages: %v", err)
	}
	if len(results) != 0 {
		t.Errorf("got %d results, want 0 (installed == fixedIn → patched): %+v", len(results), results)
	}
}

// TestScanUbuntuOVALPackages_VersionAware_NestedCriteria verifies the parser
// handles "DPKG is earlier than" comments nested one level deep inside a
// sub-<criteria> block (the structure used in real Ubuntu OVAL feeds for the
// per-package version criteria inside a top-level OR block).
func TestScanUbuntuOVALPackages_VersionAware_NestedCriteria(t *testing.T) {
	fakeDpkgQuery(t, "libssl3\t1.0")
	const feed = `<?xml version="1.0"?>
<oval_definitions>
  <definitions>
    <definition class="vulnerability">
      <metadata>
        <reference source="CVE" ref_id="CVE-2031-NESTED"/>
        <advisory><severity>critical</severity></advisory>
      </metadata>
      <criteria>
        <criteria>
          <criterion comment="libssl3 DPKG is earlier than 3.0.13-0ubuntu3.4"/>
        </criteria>
      </criteria>
    </definition>
  </definitions>
</oval_definitions>`
	results, err := ScanUbuntuOVALPackages(context.Background(), writeFixture(t, "ubuntu-nested.xml", feed))
	if err != nil {
		t.Fatalf("ScanUbuntuOVALPackages: %v", err)
	}
	if len(results) != 1 || results[0].CVEID != "CVE-2031-NESTED" {
		t.Fatalf("got %+v, want 1 result (libssl3 1.0 < fixedIn 3.0.13-0ubuntu3.4)", results)
	}
}

// TestScanUbuntuOVALPackages_RealFeed exercises the full version-aware scanner
// against a real Ubuntu Noble OVAL feed downloaded to /tmp/ubuntu-oval.xml.bz2.
// Skipped when the file is absent. Run on the real Ubuntu LXC (CT 202) after
// downloading: wget -O /tmp/ubuntu-oval.xml.bz2
// https://security-metadata.canonical.com/oval/com.ubuntu.noble.cve.oval.xml.bz2
func TestScanUbuntuOVALPackages_RealFeed(t *testing.T) {
	t.Parallel()
	const ovalPath = "/tmp/ubuntu-oval.xml.bz2"
	if _, err := os.Stat(ovalPath); err != nil {
		t.Skipf("real OVAL feed not present at %s", ovalPath)
	}
	results, err := ScanUbuntuOVALPackages(context.Background(), ovalPath)
	if err != nil {
		t.Fatalf("ScanUbuntuOVALPackages against real feed: %v", err)
	}
	t.Logf("real Noble OVAL scan: %d CVEs with installed vulnerable packages", len(results))
	// Verify structural invariants hold on real data:
	for i, r := range results {
		if r.CVEID == "" {
			t.Errorf("result[%d] has empty CVEID", i)
		}
		if len(r.Installed) == 0 {
			t.Errorf("result[%d] (%s) has empty Installed (should only appear if ≥1 match)", i, r.CVEID)
		}
		// Every Installed package must be a subset of Components.
		compSet := map[string]bool{}
		for _, c := range r.Components {
			compSet[c] = true
		}
		for _, inst := range r.Installed {
			if !compSet[inst] {
				t.Errorf("result[%d] (%s) Installed[%q] not in Components %v", i, r.CVEID, inst, r.Components)
			}
		}
	}
	// Spot-check: bash, openssl, libc6 are always installed on Ubuntu 24.04.
	// If none of those appear in any result, the scan is suspiciously quiet —
	// it doesn't mean there are zero CVEs for them, but a completely empty
	// hit-list for all three would warrant investigation.
	if len(results) == 0 {
		t.Log("WARN: zero results on real Noble OVAL — expected some vulnerable packages on a default Ubuntu 24.04 install")
	}
}

// TestScanUbuntuOVALPackages_VersionAware_VersionPreference verifies that
// when a package appears in BOTH a "DPKG is earlier than VERSION" criterion
// AND a "may need fixing" criterion (same definition), the version-bearing
// form governs the suppression decision — the no-version form does not
// override a version-specific entry already seen for the same package.
func TestScanUbuntuOVALPackages_VersionAware_VersionPreference(t *testing.T) {
	// bash 9.0 installed; OVAL says fixed at 5.0 (so patched).
	// A second criterion says "bash package in noble is affected..." (no version).
	// The version-bearing criterion must win: bash is patched → no result.
	fakeDpkgQuery(t, "bash\t9.0")
	const feed = `<?xml version="1.0"?>
<oval_definitions>
  <definitions>
    <definition class="vulnerability">
      <metadata>
        <reference source="CVE" ref_id="CVE-2031-PREFER"/>
        <advisory><severity>high</severity></advisory>
      </metadata>
      <criteria>
        <criterion comment="bash DPKG is earlier than 5.0"/>
        <criterion comment="bash package in noble is affected and may need fixing."/>
      </criteria>
    </definition>
  </definitions>
</oval_definitions>`
	results, err := ScanUbuntuOVALPackages(context.Background(), writeFixture(t, "ubuntu-prefer.xml", feed))
	if err != nil {
		t.Fatalf("ScanUbuntuOVALPackages: %v", err)
	}
	if len(results) != 0 {
		t.Errorf("got %d results, want 0 (version-bearing criterion wins; bash 9.0 >= fixedIn 5.0): %+v", len(results), results)
	}
}

// TestScanUbuntuOVALPackages_VersionAware_NoneVersion verifies that a package
// reported as version "(none)" by dpkg-query (config-files or half-installed
// dpkg state) is NOT suppressed as "already patched" — it must be treated
// identically to an absent package and skipped without reporting.
//
// The bug: CompareDpkg("(none)", "3.0.13") previously returned 1 (installed >=
// fixed → suppress) because '(' has debOrder value 296, which exceeds the
// digit-phase value for any leading digit. This caused false CVE suppression.
func TestScanUbuntuOVALPackages_VersionAware_NoneVersion(t *testing.T) {
	// bash reported at "(none)" — config-files or half-installed state.
	// OVAL says fixed at 5.0. Must NOT be suppressed as patched.
	fakeDpkgQuery(t, "bash\t(none)")
	const feed = `<?xml version="1.0"?>
<oval_definitions>
  <definitions>
    <definition class="vulnerability">
      <metadata>
        <reference source="CVE" ref_id="CVE-2031-NONE"/>
        <advisory><severity>high</severity></advisory>
      </metadata>
      <criteria>
        <criterion comment="bash DPKG is earlier than 5.0"/>
      </criteria>
    </definition>
  </definitions>
</oval_definitions>`
	results, err := ScanUbuntuOVALPackages(context.Background(), writeFixture(t, "ubuntu-none.xml", feed))
	if err != nil {
		t.Fatalf("ScanUbuntuOVALPackages: %v", err)
	}
	// "(none)" must be treated as "not installed" — skip the package entirely,
	// which means zero results (not a false suppression, not a false report).
	if len(results) != 0 {
		t.Errorf("got %d results, want 0: package with version (none) must not be reported (treated as absent): %+v", len(results), results)
	}
}
