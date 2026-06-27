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
}
