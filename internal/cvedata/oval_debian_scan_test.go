//go:build linux

package cvedata

import (
	"context"
	"os/exec"
	"testing"
)

// TestQueryInstalledDPKG_RealSystem runs the real dpkg-query against this
// container's package database (dpkg-query is present — unlike rpm, which
// these Debian-family containers/CI runners don't ship). Asserting only that
// a well-known always-installed package ("bash") appears keeps this
// deterministic without depending on the full package list's exact contents.
func TestQueryInstalledDPKG_RealSystem(t *testing.T) {
	t.Parallel()
	if _, err := exec.LookPath("dpkg-query"); err != nil {
		t.Skip("dpkg-query not available on this host")
	}
	pkgs, err := QueryInstalledDPKG(context.Background())
	if err != nil {
		t.Fatalf("QueryInstalledDPKG: %v", err)
	}
	found := false
	for _, p := range pkgs {
		if p.Name == "bash" {
			found = true
			if p.EVR == "" {
				t.Error("bash entry has empty EVR")
			}
			break
		}
	}
	if !found {
		t.Errorf("expected bash in installed package list (%d packages returned)", len(pkgs))
	}
}

// TestScanUbuntuOVALPackages_RealSystem exercises the full parse + cross-
// reference pipeline against the real dpkg database, using a synthetic OVAL
// fixture pointing at "bash" (always installed on a Debian/Ubuntu base).
func TestScanUbuntuOVALPackages_RealSystem(t *testing.T) {
	t.Parallel()
	if _, err := exec.LookPath("dpkg-query"); err != nil {
		t.Skip("dpkg-query not available on this host")
	}
	const feed = `<?xml version="1.0"?>
<oval_definitions>
  <definitions>
    <definition class="vulnerability">
      <metadata>
        <reference source="CVE" ref_id="CVE-2030-9999"/>
        <advisory><severity>critical</severity></advisory>
      </metadata>
      <criteria>
        <criterion comment="bash package in noble is affected and may need fixing."/>
        <criterion comment="some-nonexistent-pkg-xyz package in noble is affected and may need fixing."/>
      </criteria>
    </definition>
  </definitions>
</oval_definitions>`
	path := writeFixture(t, "ubuntu-real.xml", feed)
	results, err := ScanUbuntuOVALPackages(context.Background(), path)
	if err != nil {
		t.Fatalf("ScanUbuntuOVALPackages: %v", err)
	}
	if len(results) != 1 || results[0].CVEID != "CVE-2030-9999" {
		t.Fatalf("results = %+v, want 1 hit for CVE-2030-9999", results)
	}
	if len(results[0].Components) != 2 {
		t.Errorf("Components = %v, want 2 (both criterion matches, installed or not)", results[0].Components)
	}
	if len(results[0].Installed) != 1 || results[0].Installed[0] != "bash" {
		t.Errorf("Installed = %v, want [bash] (the nonexistent package must not appear)", results[0].Installed)
	}
}

// TestScanUbuntuOVALPackages_ParseError confirms a bad OVAL path/content
// short-circuits before any dpkg query.
func TestScanUbuntuOVALPackages_ParseError(t *testing.T) {
	t.Parallel()
	if _, err := ScanUbuntuOVALPackages(context.Background(), writeFixture(t, "bad.xml", "<broken")); err == nil {
		t.Error("expected error for malformed OVAL XML")
	}
}
