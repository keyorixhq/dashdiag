//go:build linux

package collectors

import (
	"testing"

	"github.com/keyorixhq/dashdiag/internal/cvedata"
	"github.com/keyorixhq/dashdiag/internal/models"
)

func TestCVENoPackageManager(t *testing.T) {
	cases := []struct {
		name string
		in   *models.CVEAllResult
		want bool
	}{
		{"nil result", nil, true},
		{"no package manager", &models.CVEAllResult{StatusReason: "no supported package manager found"}, true},
		// A package manager that merely FAILED this run must NOT fall back: the
		// failure is often transient (cold metadata, lock, load) and falling back
		// would flap the verdict between the PM and OVAL run-to-run. It stays the
		// honest "scan failed" INFO. (Validated live on SLES 16 arm64.)
		{"transient failure does NOT trigger", &models.CVEAllResult{PackageManager: "zypper", StatusReason: "zypper list-patches failed: timeout"}, false},
		// A reachable PM reporting clean is authoritative — never override with OVAL.
		{"up to date does not trigger", &models.CVEAllResult{PackageManager: "zypper", StatusReason: "no pending security patches — system is up to date"}, false},
		{"pending advisories does not trigger", &models.CVEAllResult{PackageManager: "dnf", Critical: []models.CVEAdvisory{{ID: "x"}}}, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := cveNoPackageManager(tc.in); got != tc.want {
				t.Errorf("cveNoPackageManager = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestOVALToCVEAllResult(t *testing.T) {
	results := []cvedata.OVALCVSSResult{
		{CVEID: "CVE-2026-1", CVSS3: 9.8, Severity: "Important", Installed: []string{"libgnutls30"}},
		{CVEID: "CVE-2026-2", CVSS3: 7.5, Severity: "Important", Installed: []string{"openssh"}},
		{CVEID: "CVE-2026-3", CVSS3: 5.0, Severity: "Moderate", Installed: []string{"curl"}},
		{CVEID: "CVE-2026-4", CVSS3: 2.0, Severity: "Low", Installed: []string{"tar"}},
	}
	out := ovalToCVEAllResult(results, "/var/lib/dsd/oval/suse.linux.enterprise.server.16.xml")

	if out.PackageManager != "oval:suse.linux.enterprise.server.16.xml" {
		t.Errorf("PackageManager = %q, want oval:<basename>", out.PackageManager)
	}
	if out.Total != 4 {
		t.Errorf("Total = %d, want 4", out.Total)
	}
	if len(out.Critical) != 1 || out.Critical[0].ID != "CVE-2026-1" {
		t.Errorf("Critical bucket = %+v, want [CVE-2026-1]", out.Critical)
	}
	if len(out.Important) != 1 || out.Important[0].ID != "CVE-2026-2" {
		t.Errorf("Important bucket = %+v, want [CVE-2026-2]", out.Important)
	}
	if len(out.Moderate) != 1 || len(out.Low) != 1 {
		t.Errorf("Moderate/Low = %d/%d, want 1/1", len(out.Moderate), len(out.Low))
	}
	// A CVSS≥9.0 finding must land in Critical so health raises CRIT (the whole
	// point — the air-gapped host still gets the verdict).
	if out.Critical[0].Summary != "libgnutls30" {
		t.Errorf("Critical summary = %q, want installed pkg list", out.Critical[0].Summary)
	}
}
