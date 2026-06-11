package analysis

import (
	"strings"
	"testing"

	"github.com/keyorixhq/dashdiag/internal/models"
)

// A CISA KEV match fires CRIT regardless of severity bucket — actively-exploited
// CVEs are the most urgent signal.
func TestCheckCVEHealthKEVFiresCrit(t *testing.T) {
	r := models.CVEAllResult{
		PackageManager: "dnf",
		FixCommand:     "dnf upgrade --security",
		Important:      []models.CVEAdvisory{{ID: "RHSA-1"}}, // only "high" severity...
		KEVCount:       1,
		KEVCVEs:        []string{"CVE-2021-44228"},
	}
	insights := checkCVEHealth(r)
	if len(insights) != 1 {
		t.Fatalf("expected 1 insight, got %d", len(insights))
	}
	if insights[0].Level != "CRIT" {
		t.Errorf("level = %q, want CRIT (KEV outranks severity)", insights[0].Level)
	}
	if !hasInsight(insights, "CRIT", "CISA KEV") {
		t.Errorf("message should mention CISA KEV: %q", insights[0].Message)
	}
}

// Critical advisories (CVSS >= 9.0) with no KEV match fire CRIT.
func TestCheckCVEHealthCriticalFiresCrit(t *testing.T) {
	r := models.CVEAllResult{
		PackageManager: "zypper",
		Critical:       []models.CVEAdvisory{{ID: "A"}, {ID: "B"}},
	}
	insights := checkCVEHealth(r)
	if len(insights) != 1 || insights[0].Level != "CRIT" {
		t.Fatalf("expected one CRIT, got %+v", insights)
	}
	if !hasInsight(insights, "CRIT", "2 critical") {
		t.Errorf("should report the critical count: %q", insights[0].Message)
	}
}

// Important/High advisories (CVSS >= 7.0) with no Critical/KEV fire WARN on a
// manager that publishes real severity (dnf).
func TestCheckCVEHealthImportantFiresWarn(t *testing.T) {
	r := models.CVEAllResult{
		PackageManager: "dnf",
		Important:      []models.CVEAdvisory{{ID: "A"}},
	}
	insights := checkCVEHealth(r)
	if len(insights) != 1 || insights[0].Level != "WARN" {
		t.Fatalf("expected one WARN, got %+v", insights)
	}
	if !hasInsight(insights, "WARN", "CVSS >= 7.0") {
		t.Errorf("expected CVSS-based wording for dnf, got %+v", insights)
	}
}

// apt exposes no CVSS — its name-inferred severities must not claim a CVSS
// threshold or mint a hard CRIT. A name-matched "critical" package folds into a
// single honest WARN.
func TestCheckCVEHealthAptIsNameInferredWarnNotCrit(t *testing.T) {
	r := models.CVEAllResult{
		PackageManager: "apt",
		Critical:       []models.CVEAdvisory{{ID: "A"}}, // name-guessed "critical" (e.g. openssl)
		Important:      []models.CVEAdvisory{{ID: "B"}},
	}
	insights := checkCVEHealth(r)
	if len(insights) != 1 || insights[0].Level != "WARN" {
		t.Fatalf("apt name-guess must be a single WARN, got %+v", insights)
	}
	if hasLevel(insights, "CRIT") {
		t.Error("apt name-inferred severity must not produce a CRIT")
	}
	if strings.Contains(insights[0].Message, "CVSS >=") {
		t.Errorf("apt insight must not claim a CVSS threshold, got %q", insights[0].Message)
	}
}

// Moderate/Low only stays quiet — below the WARN threshold, avoids noise.
func TestCheckCVEHealthModerateLowStaysQuiet(t *testing.T) {
	r := models.CVEAllResult{
		PackageManager: "dnf",
		Moderate:       []models.CVEAdvisory{{ID: "A"}},
		Low:            []models.CVEAdvisory{{ID: "B"}},
	}
	if got := checkCVEHealth(r); got != nil {
		t.Errorf("moderate/low only should not fire, got %+v", got)
	}
}

// A clean scan produces no insight.
func TestCheckCVEHealthCleanStaysQuiet(t *testing.T) {
	r := models.CVEAllResult{PackageManager: "dnf", Total: 0}
	if got := checkCVEHealth(r); got != nil {
		t.Errorf("clean scan should not fire, got %+v", got)
	}
}

// When the scan could not run, the row must surface as INFO ("scan unavailable"),
// never a green OK — a security check reading OK without running is a false sense
// of security. INFO does not raise the verdict.
func TestCheckCVEHealthUnavailableFiresInfo(t *testing.T) {
	cases := []struct {
		name string
		r    models.CVEAllResult
	}{
		{"no package manager", models.CVEAllResult{StatusReason: "no supported package manager found"}},
		{"zypper failed", models.CVEAllResult{PackageManager: "zypper", StatusReason: "zypper list-patches failed: timeout"}},
		{"dnf failed", models.CVEAllResult{PackageManager: "dnf", StatusReason: "dnf advisory list failed"}},
		{"arch-audit not installed", models.CVEAllResult{PackageManager: "pacman", StatusReason: "install arch-audit for CVE scanning: pacman -S arch-audit"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			insights := checkCVEHealth(tc.r)
			if len(insights) != 1 || insights[0].Level != "INFO" {
				t.Fatalf("expected one INFO insight, got %+v", insights)
			}
			if !hasInsight(insights, "INFO", "scan unavailable") {
				t.Errorf("message should say scan unavailable: %q", insights[0].Message)
			}
		})
	}
}

// A clean scan (scanner ran, found nothing) must NOT be misclassified as
// unavailable — it stays a legitimate quiet OK.
func TestCVEScanUnavailable_CleanIsAvailable(t *testing.T) {
	clean := []models.CVEAllResult{
		{PackageManager: "dnf", StatusReason: "no pending security advisories — system is up to date"},
		{PackageManager: "zypper", StatusReason: "no pending security patches — system is up to date"},
		{PackageManager: "apt", StatusReason: "no pending upgrades found"},
		{PackageManager: "pacman", StatusReason: "no vulnerable packages found — system is up to date"},
	}
	for _, r := range clean {
		if cveScanUnavailable(r) {
			t.Errorf("clean scan (%s) wrongly classified as unavailable: %q", r.PackageManager, r.StatusReason)
		}
		if got := checkCVEHealth(r); got != nil {
			t.Errorf("clean scan (%s) should stay quiet, got %+v", r.PackageManager, got)
		}
	}
}

// The CVE collector result flows through applyOne (the type dispatch) as a CRIT
// insight on the "CVE" check — the integration point dsd health relies on.
func TestCVEHealthDispatchProducesInsight(t *testing.T) {
	r := &models.CVEAllResult{PackageManager: "dnf", Critical: []models.CVEAdvisory{{ID: "A"}}}
	insights := applyOneExtended(r, Thresholds{})
	if !hasInsight(insights, "CRIT", "critical security advisory") {
		t.Errorf("dispatch should yield a CRIT CVE insight, got %+v", insights)
	}
	for _, in := range insights {
		if in.Check != "CVE" {
			t.Errorf("insight Check = %q, want CVE", in.Check)
		}
	}
}
