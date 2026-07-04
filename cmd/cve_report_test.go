package cmd

import (
	"strings"
	"testing"

	"github.com/keyorixhq/dashdiag/internal/cvedata"
	"github.com/keyorixhq/dashdiag/internal/models"
)

// Golden-output tests for cve.go's per-CVE and OVAL result printers. Plain
// data structs, no live I/O. No t.Parallel() (corrupts captureStdout's shared
// os.Stdout swap).

func TestPrintCVEResultVulnerable(t *testing.T) {
	out := captureStdout(t, func() {
		printCVEResult(&models.CVEResult{
			CVE: "CVE-2026-0001", PackageManager: "dnf", Status: models.CVEVulnerable,
			AffectedPackages: []models.CVEPackage{{Name: "openssl", Advisory: "RHSA-2026:001", Severity: "critical"}},
			FixCommand:       "dnf update openssl",
		})
	})
	if !strings.Contains(out, "VULNERABLE") || !strings.Contains(out, "openssl") {
		t.Errorf("a vulnerable result should list the affected package, got:\n%s", out)
	}
	if !strings.Contains(out, "dnf update openssl") {
		t.Errorf("the fix command should be shown, got:\n%s", out)
	}
}

func TestPrintCVEResultKEV(t *testing.T) {
	out := captureStdout(t, func() {
		printCVEResult(&models.CVEResult{
			CVE: "CVE-2026-0002", Status: models.CVEVulnerable,
			KnownExploited: true, KEVDateAdded: "2026-01-01", KEVRansomware: true,
		})
	})
	if !strings.Contains(out, "CISA KEV") || !strings.Contains(out, "2026-01-01") {
		t.Errorf("a KEV-listed CVE should show the CISA KEV callout with its date, got:\n%s", out)
	}
	if !strings.Contains(out, "ransomware") {
		t.Errorf("a ransomware-linked KEV should say so — patch-immediately urgency, got:\n%s", out)
	}
}

func TestPrintCVEResultPatchedAndNotAffected(t *testing.T) {
	patched := captureStdout(t, func() {
		printCVEResult(&models.CVEResult{CVE: "CVE-2026-0003", Status: models.CVEPatched, StatusReason: "fixed in 3.0.5-1"})
	})
	if !strings.Contains(patched, "PATCHED") || !strings.Contains(patched, "fixed in 3.0.5-1") {
		t.Errorf("a patched CVE should show the reason, got:\n%s", patched)
	}

	notAffected := captureStdout(t, func() {
		printCVEResult(&models.CVEResult{CVE: "CVE-2026-0004", Status: models.CVENotAffected})
	})
	if !strings.Contains(notAffected, "NOT AFFECTED") {
		t.Errorf("a not-affected CVE should say so, got:\n%s", notAffected)
	}
}

func TestPrintCVEResultUnknown(t *testing.T) {
	out := captureStdout(t, func() {
		printCVEResult(&models.CVEResult{CVE: "CVE-2026-0005", Status: models.CVEUnknown,
			StatusReason: "package manager query failed", FallbackURL: "https://nvd.nist.gov/vuln/detail/CVE-2026-0005"})
	})
	if !strings.Contains(out, "UNKNOWN") || !strings.Contains(out, "query failed") {
		t.Errorf("an unknown-status CVE must not silently omit the reason, got:\n%s", out)
	}
	if !strings.Contains(out, "nvd.nist.gov") {
		t.Errorf("an unknown status should point to a manual-check URL, got:\n%s", out)
	}
}

func TestPrintOVALResult(t *testing.T) {
	notInOVAL := captureStdout(t, func() { printOVALResult(&cvedata.OVALResult{CVE: "CVE-2026-0001", Found: false}) })
	if !strings.Contains(notInOVAL, "NOT IN OVAL") {
		t.Errorf("a CVE absent from the OVAL feed should say so — not a scan failure, got:\n%s", notInOVAL)
	}

	notAffected := captureStdout(t, func() {
		printOVALResult(&cvedata.OVALResult{CVE: "CVE-2026-0002", Found: true, Severity: "Critical"})
	})
	if !strings.Contains(notAffected, "NOT AFFECTED") {
		t.Errorf("a found-but-no-vulnerable-packages result should say not affected, got:\n%s", notAffected)
	}

	vulnerable := captureStdout(t, func() {
		printOVALResult(&cvedata.OVALResult{CVE: "CVE-2026-0003", Found: true, Severity: "Critical",
			Packages: []cvedata.OVALPackageMatch{{Name: "glibc", Installed: "2.28-1", FixedIn: "2.28-2"}}})
	})
	if !strings.Contains(vulnerable, "glibc") || !strings.Contains(vulnerable, "1 package(s)") {
		t.Errorf("a vulnerable OVAL result should name the affected package, got:\n%s", vulnerable)
	}
}

func TestPrintOVALScanResults(t *testing.T) {
	clean := captureStdout(t, func() { printOVALScanResults(nil) })
	if !strings.Contains(clean, "No vulnerable packages found") {
		t.Errorf("an empty result set should say so, got:\n%s", clean)
	}

	// Bucketed by CVSS: critical (>=9.0), high (>=7.0), medium (>=4.0), low.
	// A KEV-severity CVE and a low-severity one must land in different buckets.
	results := []cvedata.OVALCVSSResult{
		{CVEID: "CVE-2026-0001", CVSS3: 9.8, Severity: "Critical", Installed: []string{"openssl"}},
		{CVEID: "CVE-2026-0002", CVSS3: 3.1, Severity: "Low", Installed: []string{"curl"}},
	}
	out := captureStdout(t, func() { printOVALScanResults(results) })
	if !strings.Contains(out, "Critical (CVSS") || !strings.Contains(out, "Low (CVSS") {
		t.Errorf("results should be bucketed by CVSS severity, got:\n%s", out)
	}
	if !strings.Contains(out, "openssl") || !strings.Contains(out, "curl") {
		t.Errorf("each bucket should list its affected packages, got:\n%s", out)
	}
	if !strings.Contains(out, "2 finding(s)") {
		t.Errorf("the total finding count should be shown, got:\n%s", out)
	}
}
