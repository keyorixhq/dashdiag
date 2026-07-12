//go:build linux

package cvedata

import (
	"context"
	"os/exec"
	"path/filepath"
	"testing"
)

// rpmUnavailable reports whether the "rpm" binary is absent from PATH in the
// current test environment. The RPM-backed scanners (RHEL/SUSE) shell out to
// it, and this repo's containers/CI runners are Debian-family and don't ship
// it — so QueryInstalledRPM deterministically errors here. Guarding on
// exec.LookPath (rather than assuming absence) keeps the test honest on a
// host that DOES have rpm installed, where it would skip instead of asserting
// a false expectation.
func rpmUnavailable(t *testing.T) {
	t.Helper()
	if _, err := exec.LookPath("rpm"); err == nil {
		t.Skip("rpm is available on this host — the guaranteed-failure path this test checks does not apply")
	}
}

// ── scanRHELOVALPackages / ScanOVALPackages (RHEL branch) ──────────────────

func TestScanRHELOVALPackages_ParseError(t *testing.T) {
	t.Parallel()
	if _, err := scanRHELOVALPackages(context.Background(), filepath.Join(t.TempDir(), "missing.xml")); err == nil {
		t.Error("expected error for missing OVAL file")
	}
}

func TestScanRHELOVALPackages_QueryInstalledRPMFails(t *testing.T) {
	t.Parallel()
	rpmUnavailable(t)
	path := writeFixture(t, "rhel.xml", rhelOVAL)
	if _, err := scanRHELOVALPackages(context.Background(), path); err == nil {
		t.Error("expected error when rpm is unavailable to query installed packages")
	}
}

// sniffableRHELOVAL carries a "redhat.com" content marker so sniffOVALVendor
// routes it to the RHEL scanner purely from content, even under a neutral
// filename — distinct from TestScanOVALPackages_DispatchFallsBackToRHEL
// below, which exercises the fallback-when-inconclusive path instead. The
// XML declaration must stay first, so the marker lives in a comment after it.
const sniffableRHELOVAL = `<?xml version="1.0"?>
<!-- source: https://access.redhat.com/security/data/oval/ -->
<oval_definitions>
  <definitions>
    <definition class="vulnerability">
      <metadata>
        <reference source="CVE" ref_id="CVE-2030-0002"/>
        <advisory>
          <severity>Critical</severity>
          <cve cvss3="9.5/CVSS:3.1/AV:N" impact="critical">CVE-2030-0002</cve>
          <affected>
            <resolution state="Affected"><component>testpkg</component></resolution>
          </affected>
        </advisory>
      </metadata>
    </definition>
  </definitions>
</oval_definitions>`

func TestScanOVALPackages_DispatchToRHELOnContentSniff(t *testing.T) {
	t.Parallel()
	rpmUnavailable(t)
	path := writeFixture(t, "feed.xml", sniffableRHELOVAL) // neutral filename, content decides
	if _, err := ScanOVALPackages(context.Background(), path); err == nil {
		t.Error("expected the RHEL dispatch path to surface the rpm-unavailable error")
	}
}

// ── ScanSUSEOVALPackages / ScanOVALPackages (SUSE branch) ───────────────────

func TestScanSUSEOVALPackages_LoadError(t *testing.T) {
	t.Parallel()
	if _, err := ScanSUSEOVALPackages(context.Background(), filepath.Join(t.TempDir(), "missing.xml")); err == nil {
		t.Error("expected error for missing OVAL file")
	}
}

func TestScanSUSEOVALPackages_QueryInstalledRPMFails(t *testing.T) {
	t.Parallel()
	rpmUnavailable(t)
	path := writeFixture(t, "suse.xml", suseOVAL)
	if _, err := ScanSUSEOVALPackages(context.Background(), path); err == nil {
		t.Error("expected error when rpm is unavailable to query installed packages")
	}
}

func TestScanOVALPackages_DispatchToSUSEByFilename(t *testing.T) {
	t.Parallel()
	rpmUnavailable(t)
	// Content doesn't sniff to any vendor, so dispatch falls back to the
	// filename hint — "sles" in the name routes to the SUSE scanner.
	path := writeFixture(t, "sles15-custom.xml", suseOVAL)
	if _, err := ScanOVALPackages(context.Background(), path); err == nil {
		t.Error("expected the SUSE dispatch path (by filename) to surface the rpm-unavailable error")
	}
}

// sniffableSUSEOVAL carries a content marker ("suse.linux.enterprise") that
// sniffOVALVendor recognises, so ScanOVALPackages routes to
// ScanSUSEOVALPackages purely from content, distinct from
// TestScanOVALPackages_DispatchToSUSEByFilename above (filename-only hint).
const sniffableSUSEOVAL = `<?xml version="1.0"?>
<!-- source: suse.linux.enterprise oval feed -->
<oval_definitions>
  <definitions>
    <definition id="oval:test:def:1" class="patch">
      <metadata>
        <title>Security update for foo (Important)</title>
        <reference source="CVE" ref_id="CVE-2030-2222"/>
        <advisory><severity>important</severity></advisory>
      </metadata>
      <criteria>
        <criterion test_ref="oval:tst:1" comment="foo-1.0-1 is installed"/>
      </criteria>
    </definition>
  </definitions>
</oval_definitions>`

func TestScanOVALPackages_DispatchToSUSEOnContentSniff(t *testing.T) {
	t.Parallel()
	rpmUnavailable(t)
	// Neutral filename — content alone must route this to the SUSE scanner.
	path := writeFixture(t, "feed.xml", sniffableSUSEOVAL)
	if _, err := ScanOVALPackages(context.Background(), path); err == nil {
		t.Error("expected the SUSE dispatch path (by content sniff) to surface the rpm-unavailable error")
	}
}

// TestScanOVALPackages_DispatchFallsBackToRHEL exercises the RHEL scanner via
// content sniffing: rhelOVAL's "RHSA-2024:1" reference ID contains the "rhsa"
// marker sniffOVALVendor looks for, so this reaches scanRHELOVALPackages via
// the "rhel" case in the switch (oval_rhel.go:203-204), not the trailing
// default fallback at line 213 — that line is covered separately by
// TestScanOVALPackages_DispatchFallsBackToRHELWhenContentIsFullyNeutral below.
func TestScanOVALPackages_DispatchFallsBackToRHEL(t *testing.T) {
	t.Parallel()
	rpmUnavailable(t)
	path := writeFixture(t, "neutral-name.xml", rhelOVAL)
	if _, err := ScanOVALPackages(context.Background(), path); err == nil {
		t.Error("expected the RHEL dispatch path to surface the rpm-unavailable error")
	}
}

// fullyNeutralOVAL carries no vendor content marker at all (no "rhsa"/
// "redhat"/"canonical"/"suse" substring anywhere), and is written under a
// filename that matches neither the Ubuntu/Debian nor SUSE filename hints —
// so ScanOVALPackages must exhaust every dispatch check and reach the final
// unconditional "return scanRHELOVALPackages(...)" default at the end of the
// function (oval_rhel.go:213), not any of the earlier switch/if branches.
const fullyNeutralOVAL = `<?xml version="1.0"?>
<oval_definitions>
  <definitions>
    <definition class="vulnerability">
      <metadata>
        <reference source="CVE" ref_id="CVE-2030-3333"/>
        <advisory>
          <severity>Important</severity>
          <cve cvss3="7.5/CVSS:3.1/AV:N" impact="important">CVE-2030-3333</cve>
          <affected><resolution state="Affected"><component>testpkg</component></resolution></affected>
        </advisory>
      </metadata>
    </definition>
  </definitions>
</oval_definitions>`

func TestScanOVALPackages_DispatchFallsBackToRHELWhenContentIsFullyNeutral(t *testing.T) {
	t.Parallel()
	rpmUnavailable(t)
	path := writeFixture(t, "generic-feed.xml", fullyNeutralOVAL)
	if _, err := ScanOVALPackages(context.Background(), path); err == nil {
		t.Error("expected the default (final fallback) RHEL dispatch path to surface the rpm-unavailable error")
	}
}

// ── ScanOVALPackages (Ubuntu branch, real dpkg-query) ────────────────────────

// suseSniffableUbuntuOVAL carries a content marker ("canonical") that
// sniffOVALVendor recognises, so ScanOVALPackages routes to
// ScanUbuntuOVALPackages regardless of the file's name.
const sniffableUbuntuOVAL = `<?xml version="1.0"?>
<!-- generated by canonical -->
<oval_definitions>
  <definitions>
    <definition class="vulnerability">
      <metadata>
        <reference source="CVE" ref_id="CVE-2030-0001"/>
        <advisory><severity>high</severity></advisory>
      </metadata>
      <criteria>
        <criterion comment="bash package in noble is affected and may need fixing."/>
      </criteria>
    </definition>
  </definitions>
</oval_definitions>`

// TestScanOVALPackages_DispatchToUbuntuByFilename exercises the filename-hint
// fallback for Ubuntu/Debian: content doesn't sniff to any vendor (no
// "canonical"/"ubuntu.com" marker), so dispatch falls back to the "ubuntu" in
// the filename — distinct from the content-sniff path exercised by
// TestScanOVALPackages_DispatchToUbuntuAndFindsRealPackage below. Uses the
// same sniffableUbuntuOVAL feed (naming "bash", always installed) but under a
// neutral-content/ubuntu-named file so only the filename hint can route it.
func TestScanOVALPackages_DispatchToUbuntuByFilename(t *testing.T) {
	t.Parallel()
	if _, err := exec.LookPath("dpkg-query"); err != nil {
		t.Skip("dpkg-query not available on this host")
	}
	const feed = `<?xml version="1.0"?>
<oval_definitions>
  <definitions>
    <definition class="vulnerability">
      <metadata>
        <reference source="CVE" ref_id="CVE-2030-0009"/>
        <advisory><severity>high</severity></advisory>
      </metadata>
      <criteria>
        <criterion comment="bash package in noble is affected and may need fixing."/>
      </criteria>
    </definition>
  </definitions>
</oval_definitions>`
	// No vendor content marker present -> sniffOVALVendor returns "" and
	// dispatch must fall back to the "ubuntu" substring in the filename.
	path := writeFixture(t, "ubuntu-custom-feed.xml", feed)
	results, err := ScanOVALPackages(context.Background(), path)
	if err != nil {
		t.Fatalf("ScanOVALPackages: %v", err)
	}
	if len(results) != 1 || results[0].CVEID != "CVE-2030-0009" {
		t.Fatalf("results = %+v, want 1 hit for CVE-2030-0009 (bash is always installed)", results)
	}
}

// TestScanOVALPackages_DispatchToUbuntuAndFindsRealPackage exercises the full
// Ubuntu dispatch path against the REAL system dpkg database (dpkg-query is
// present in this repo's containers, unlike rpm). "bash" is present on any
// Debian/Ubuntu base image, so this is a deterministic pass, not a flaky
// dependency on exact package contents.
func TestScanOVALPackages_DispatchToUbuntuAndFindsRealPackage(t *testing.T) {
	t.Parallel()
	if _, err := exec.LookPath("dpkg-query"); err != nil {
		t.Skip("dpkg-query not available on this host")
	}
	path := writeFixture(t, "feed.xml", sniffableUbuntuOVAL)
	results, err := ScanOVALPackages(context.Background(), path)
	if err != nil {
		t.Fatalf("ScanOVALPackages: %v", err)
	}
	if len(results) != 1 || results[0].CVEID != "CVE-2030-0001" {
		t.Fatalf("results = %+v, want 1 hit for CVE-2030-0001 (bash is always installed)", results)
	}
	if len(results[0].Installed) != 1 || results[0].Installed[0] != "bash" {
		t.Errorf("Installed = %v, want [bash]", results[0].Installed)
	}
}

// ── CheckCVEFromOVAL (found path, RPM query) ────────────────────────────────

func TestCheckCVEFromOVAL_FoundButRPMQueryFails(t *testing.T) {
	t.Parallel()
	rpmUnavailable(t)
	path := writeFixture(t, "suse.xml", suseOVAL)
	res, err := CheckCVEFromOVAL(context.Background(), path, "CVE-2025-0001")
	if err == nil {
		t.Fatal("expected error once the CVE is found and rpm querying fails")
	}
	// The definition-match fields are still populated before the query fails.
	if res == nil || !res.Found || res.Summary == "" {
		t.Errorf("result = %+v, want Found=true with Summary populated despite the query error", res)
	}
}
