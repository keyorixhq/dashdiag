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

// TestCheckCVEHealth_KEVCatalogReadFailed covers internal-collectors-06-03: a
// present-but-broken KEV catalog (corrupt JSON, truncated gzip, wrong schema)
// previously read identically to "no catalog available" — silently
// suppressing the KEV-driven CRIT escalation with no indication
// cross-referencing didn't run. It must now append an additional INFO
// alongside whatever severity insight the plain package-manager rating
// still produces.
func TestCheckCVEHealth_KEVCatalogReadFailed(t *testing.T) {
	r := models.CVEAllResult{
		PackageManager:       "zypper",
		Critical:             []models.CVEAdvisory{{ID: "A"}},
		KEVCatalogReadFailed: true,
	}
	insights := checkCVEHealth(r)
	if len(insights) != 2 {
		t.Fatalf("expected the CRIT plus an additional KEV-unread INFO, got %d: %+v", len(insights), insights)
	}
	if !hasInsight(insights, "CRIT", "critical security advisory") {
		t.Errorf("the underlying severity CRIT must still fire, got %+v", insights)
	}
	if !hasInsight(insights, "INFO", "KEV cross-reference could not run") {
		t.Errorf("expected an INFO disclosing the failed KEV cross-reference, got %+v", insights)
	}
}

// A clean scan (nothing pending) with a broken KEV catalog must stay quiet —
// there was nothing for a working catalog to have escalated, so disclosing
// the load failure here would be pure noise.
func TestCheckCVEHealth_KEVCatalogReadFailedButNothingPendingStaysQuiet(t *testing.T) {
	r := models.CVEAllResult{PackageManager: "zypper", KEVCatalogReadFailed: true}
	if got := checkCVEHealth(r); len(got) != 0 {
		t.Errorf("expected silence when nothing is pending, got %+v", got)
	}
}

// Critical-rated advisories with no KEV match fire CRIT.
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

// Important/High-rated advisories with no Critical/KEV fire WARN on a manager
// that publishes a vendor severity rating (dnf). The message must reference the
// rating, not assert a CVSS score the advisory-list scan never measured (the
// bucket comes from dnf's "Important" label, not a number).
func TestCheckCVEHealthImportantFiresWarn(t *testing.T) {
	r := models.CVEAllResult{
		PackageManager: "dnf",
		Important:      []models.CVEAdvisory{{ID: "A"}},
	}
	insights := checkCVEHealth(r)
	if len(insights) != 1 || insights[0].Level != "WARN" {
		t.Fatalf("expected one WARN, got %+v", insights)
	}
	if !hasInsight(insights, "WARN", "rates these High/Important") {
		t.Errorf("expected rating-based wording for dnf, got %+v", insights)
	}
	if strings.Contains(insights[0].Message, "CVSS >=") {
		t.Errorf("dnf advisory-list scan reads a severity label, not a CVSS score — must not claim a CVSS threshold, got %q", insights[0].Message)
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
		{"apt failed (lock/broken sources)", models.CVEAllResult{PackageManager: "apt", StatusReason: "apt-get --simulate upgrade failed: exit status 100"}},
		{"arch-audit not installed", models.CVEAllResult{PackageManager: "pacman", StatusReason: "install arch-audit for CVE scanning: pacman -S arch-audit"}},
		// Cold/stale index: zero advisories but the cache was never refreshed, so
		// "no CVEs" was never actually confirmed — must be INFO, not silent clean
		// (the security cold-cache false-OK fix).
		{"stale index, exposure not verified", models.CVEAllResult{PackageManager: "dnf", StatusReason: "update metadata is 40 days old (stale) — CVE exposure NOT verified; refresh the index and rescan"}},
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

// BUG-098: ScanFailed must be checked directly, not inferred from StatusReason
// substrings — a scanner message can be reworded (e.g. to distinguish a cold-cache
// timeout from a generic failure) without the substrings being updated, and a
// pattern-match-only check would then silently render a failed scan as OK. Found
// live: rewording scanAllDNF's timeout message to be more honest flipped this
// exact case from INFO to a false "OK" before ScanFailed was checked directly.
func TestCVEScanUnavailable_ScanFailedOverridesWording(t *testing.T) {
	r := models.CVEAllResult{
		PackageManager: "dnf",
		ScanFailed:     true,
		StatusReason:   "dnf advisory scan timed out — likely a cold metadata cache or slow mirror; retry",
	}
	if !cveScanUnavailable(r) {
		t.Errorf("ScanFailed=true must be treated as unavailable regardless of wording, got available for %q", r.StatusReason)
	}
	insights := checkCVEHealth(r)
	if len(insights) != 1 || insights[0].Level != "INFO" {
		t.Fatalf("expected one INFO insight for a failed scan, got %+v", insights)
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
