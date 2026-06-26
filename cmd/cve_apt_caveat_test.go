package cmd

import (
	"strings"
	"testing"

	"github.com/keyorixhq/dashdiag/internal/models"
)

// TestPrintAllCVEsAptCaveat: `dsd cve --all` on apt buckets severity by package
// NAME (apt has no CVSS), so the red CRITICAL label must carry the "inferred,
// not confirmed" caveat — matching dsd health --cve. dnf/zypper expose a real
// severity and must NOT show the caveat.
func TestPrintAllCVEsAptCaveat(t *testing.T) {
	apt := &models.CVEAllResult{
		PackageManager: "apt", Total: 1,
		Critical: []models.CVEAdvisory{{ID: "openssl", Severity: "critical"}},
	}
	out := captureStdout(t, func() { printAllCVEs(apt) })
	if !strings.Contains(out, "INFERRED from package name") {
		t.Errorf("apt cve --all must caveat name-inferred severity; got:\n%s", out)
	}

	dnf := &models.CVEAllResult{
		PackageManager: "dnf", Total: 1,
		Critical: []models.CVEAdvisory{{ID: "RHSA-2026:1", Severity: "Critical"}},
	}
	out2 := captureStdout(t, func() { printAllCVEs(dnf) })
	if strings.Contains(out2, "INFERRED") {
		t.Errorf("dnf has real CVSS — must NOT show the apt name-inference caveat; got:\n%s", out2)
	}
}
