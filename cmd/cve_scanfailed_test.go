package cmd

import (
	"strings"
	"testing"

	"github.com/keyorixhq/dashdiag/internal/models"
)

// TestPrintAllCVEsScanFailed: a scan that could NOT run (no repo access, scanner
// absent) reports Total==0 but ScanFailed==true. That is "exposure UNKNOWN", not
// "up to date" — the renderer must NOT print the green ✅, or an operator on a host
// that can't reach its repos reads a failed scan as clean (the false-OK class).
// Found live on a fresh AlmaLinux 10.2 VMware guest with no DNS: `dsd cve --all`
// printed "✅ dnf advisory list failed".
func TestPrintAllCVEsScanFailed(t *testing.T) {
	failed := &models.CVEAllResult{
		PackageManager: "dnf", Total: 0, ScanFailed: true,
		StatusReason: "dnf advisory list failed — could not verify CVE exposure (no repo access?)",
	}
	out := captureStdout(t, func() { printAllCVEs(failed) })
	if strings.Contains(out, "✅") {
		t.Errorf("a FAILED scan must not render a green ✅ (false-OK); got:\n%s", out)
	}
	if !strings.Contains(out, "⚠️") || !strings.Contains(out, "NOT verify") && !strings.Contains(out, "could not") {
		t.Errorf("a failed scan must surface as an unverified warning; got:\n%s", out)
	}

	// A genuinely clean scan (Total==0, ScanFailed==false) still shows the ✅.
	clean := &models.CVEAllResult{
		PackageManager: "dnf", Total: 0,
		StatusReason: "no pending security advisories — system is up to date",
	}
	out2 := captureStdout(t, func() { printAllCVEs(clean) })
	if !strings.Contains(out2, "✅") {
		t.Errorf("a clean up-to-date scan should still show ✅; got:\n%s", out2)
	}

	// Total==0 with no StatusReason set at all falls back to the generic
	// "up to date" message (a different branch than the StatusReason case above).
	cleanNoReason := &models.CVEAllResult{PackageManager: "dnf", Total: 0}
	out3 := captureStdout(t, func() { printAllCVEs(cleanNoReason) })
	if !strings.Contains(out3, "No pending security advisories") {
		t.Errorf("Total==0 with no StatusReason should print the generic up-to-date line; got:\n%s", out3)
	}

	// ScanFailed with no StatusReason at all falls back to the generic
	// "could not run" warning (distinct from the explicit-reason case above).
	failedNoReason := &models.CVEAllResult{PackageManager: "dnf", Total: 0, ScanFailed: true}
	out4 := captureStdout(t, func() { printAllCVEs(failedNoReason) })
	if !strings.Contains(out4, "could not run") {
		t.Errorf("ScanFailed with no StatusReason should print the generic could-not-run warning; got:\n%s", out4)
	}
}

// TestPrintAllCVEsKEVFixCommandSubscription covers the KEVCount>0 callout,
// the "to fix all" FixCommand line, and the SubscriptionNote line — none
// exercised by the scan-failed/apt-caveat tests above.
func TestPrintAllCVEsKEVFixCommandSubscription(t *testing.T) {
	r := &models.CVEAllResult{
		PackageManager: "dnf", Total: 2,
		KEVCount: 1, KEVCVEs: []string{"CVE-2026-0099"},
		Critical:         []models.CVEAdvisory{{ID: "RHSA-2026:1", Severity: "Critical"}},
		FixCommand:       "dnf update --security",
		SubscriptionNote: "Some advisories require an active Red Hat subscription.",
	}
	out := captureStdout(t, func() { printAllCVEs(r) })
	if !strings.Contains(out, "actively exploited (CISA KEV)") || !strings.Contains(out, "CVE-2026-0099") {
		t.Errorf("a KEV-listed advisory should show the CISA KEV callout, got:\n%s", out)
	}
	if !strings.Contains(out, "to fix all:  dnf update --security") {
		t.Errorf("a set FixCommand should show the to-fix-all line, got:\n%s", out)
	}
	if !strings.Contains(out, "Red Hat subscription") {
		t.Errorf("a set SubscriptionNote should be shown, got:\n%s", out)
	}
}
