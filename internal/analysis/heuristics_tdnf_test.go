package analysis

import (
	"testing"

	"github.com/keyorixhq/dashdiag/internal/models"
)

// VMware Photon OS (tdnf) publishes PHSA advisories with NO per-package CVSS.
// scanAllTDNF buckets every advisory as Important; the health fold MUST render a
// single WARN (never a CRIT) — the same no-CVSS discipline as apt. Before tdnf
// support, Photon read as an "unknown" package manager and these advisories were
// INVISIBLE (a silent false-OK on VMware's own distro).
func TestCheckCVEHealthTDNFFoldsToWarn(t *testing.T) {
	r := models.CVEAllResult{
		PackageManager: "tdnf",
		FixCommand:     "tdnf update --security",
		Important: []models.CVEAdvisory{
			{ID: "PHSA-2026-5.0-0830", CVEs: "CVE-2026-34743"},
			{ID: "PHSA-2026-5.0-0885", CVEs: "CVE-2026-3184"},
		},
	}
	insights := checkCVEHealth(r)
	if len(insights) != 1 {
		t.Fatalf("expected 1 insight, got %d: %+v", len(insights), insights)
	}
	if insights[0].Level != "WARN" {
		t.Errorf("level = %q, want WARN (Photon advisories carry no CVSS — never a minted CRIT)", insights[0].Level)
	}
	if !hasInsight(insights, "WARN", "tdnf") {
		t.Errorf("message should name the tdnf source: %q", insights[0].Message)
	}
}

// A tdnf scan that found nothing stays quiet (below WARN) — not a false alarm.
func TestCheckCVEHealthTDNFCleanIsQuiet(t *testing.T) {
	r := models.CVEAllResult{
		PackageManager: "tdnf",
		StatusReason:   "no pending security advisories — system is up to date",
	}
	if insights := checkCVEHealth(r); len(insights) != 0 {
		t.Errorf("clean tdnf scan must be quiet, got %+v", insights)
	}
}

// The packages collector path: tdnf security updates fold to WARN with the
// no-CVSS caveat, never the CriticalUpdates→CRIT path.
func TestCheckPackageUpdatesTDNFWarnNeverCrit(t *testing.T) {
	pkg := models.PackagesInfo{
		Checked:          true,
		PackageManager:   "tdnf",
		SecurityUpdates:  16,
		ImportantUpdates: 16,
	}
	insights := checkPackageUpdates(pkg)
	if len(insights) != 1 {
		t.Fatalf("expected 1 insight, got %d: %+v", len(insights), insights)
	}
	if insights[0].Level != "WARN" {
		t.Errorf("level = %q, want WARN", insights[0].Level)
	}
	if !hasInsight(insights, "WARN", "tdnf") {
		t.Errorf("message should name tdnf: %q", insights[0].Message)
	}
}
