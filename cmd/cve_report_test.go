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

// TestPrintCVEResultCVSSAndFixState covers the CVSS3Score line (with and
// without ThreatSev) and the Red Hat fix-state line (with and without
// AffectedPkg), plus the VULNERABLE status's FallbackURL "more info" line —
// none exercised by the tests above.
func TestPrintCVEResultCVSSAndFixState(t *testing.T) {
	withSev := captureStdout(t, func() {
		printCVEResult(&models.CVEResult{CVE: "CVE-2026-0010", Status: models.CVENotAffected,
			CVSS3Score: "7.5", ThreatSev: "high"})
	})
	if !strings.Contains(withSev, "CVSS3: 7.5") || !strings.Contains(withSev, "(high)") {
		t.Errorf("a CVSS score with a known severity should show both, got:\n%s", withSev)
	}

	noSev := captureStdout(t, func() {
		printCVEResult(&models.CVEResult{CVE: "CVE-2026-0011", Status: models.CVENotAffected,
			CVSS3Score: "5.0"})
	})
	if !strings.Contains(noSev, "unknown severity") {
		t.Errorf("a CVSS score with no ThreatSev should fall back to unknown severity, got:\n%s", noSev)
	}

	fixStateWithPkg := captureStdout(t, func() {
		printCVEResult(&models.CVEResult{CVE: "CVE-2026-0012", Status: models.CVENotAffected,
			FixState: "Will not fix", AffectedPkg: "openssl-libs"})
	})
	if !strings.Contains(fixStateWithPkg, "Will not fix") || !strings.Contains(fixStateWithPkg, "openssl-libs") {
		t.Errorf("a fix state with an affected package should show both, got:\n%s", fixStateWithPkg)
	}

	fixStateNoPkg := captureStdout(t, func() {
		printCVEResult(&models.CVEResult{CVE: "CVE-2026-0013", Status: models.CVENotAffected, FixState: "Fixed"})
	})
	if !strings.Contains(fixStateNoPkg, "Red Hat fix state: Fixed") {
		t.Errorf("a fix state with no affected package should still print, got:\n%s", fixStateNoPkg)
	}

	vulnWithURL := captureStdout(t, func() {
		printCVEResult(&models.CVEResult{CVE: "CVE-2026-0014", Status: models.CVEVulnerable,
			FallbackURL: "https://nvd.nist.gov/vuln/detail/CVE-2026-0014"})
	})
	if !strings.Contains(vulnWithURL, "more info:") || !strings.Contains(vulnWithURL, "nvd.nist.gov") {
		t.Errorf("a vulnerable result with a fallback URL should show the more-info line, got:\n%s", vulnWithURL)
	}
}

// TestPrintAdvisoryGroup covers the empty (no-op), CVEs-set, and
// Summary-fallback branches — printAllCVEs' KEV test above only exercises the
// bare-ID (neither CVEs nor Summary set) branch.
func TestPrintAdvisoryGroup(t *testing.T) {
	if out := captureStdout(t, func() { printAdvisoryGroup("CRITICAL", nil) }); out != "" {
		t.Errorf("an empty advisory list should print nothing, got:\n%s", out)
	}

	withCVEs := captureStdout(t, func() {
		printAdvisoryGroup("CRITICAL", []models.CVEAdvisory{{ID: "RHSA-2026:1", CVEs: "CVE-2026-0001, CVE-2026-0002"}})
	})
	if !strings.Contains(withCVEs, "CVE-2026-0001, CVE-2026-0002") {
		t.Errorf("a set CVEs field should be shown, got:\n%s", withCVEs)
	}

	withSummary := captureStdout(t, func() {
		printAdvisoryGroup("CRITICAL", []models.CVEAdvisory{{ID: "openssl", Summary: "OpenSSL security update addressing multiple CVEs"}})
	})
	if !strings.Contains(withSummary, "OpenSSL security update") {
		t.Errorf("an empty CVEs field should fall back to the Summary, got:\n%s", withSummary)
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

// TestPrintOVALScanResultsHighAndMediumBuckets covers the two bucket branches
// (CVSS 7.0-9.0 "High" and 4.0-7.0 "Medium") not exercised by the
// Critical/Low-only test above.
func TestPrintOVALScanResultsHighAndMediumBuckets(t *testing.T) {
	results := []cvedata.OVALCVSSResult{
		{CVEID: "CVE-2026-0003", CVSS3: 8.1, Severity: "High", Installed: []string{"nginx"}},
		{CVEID: "CVE-2026-0004", CVSS3: 5.5, Severity: "Medium", Installed: []string{"bash"}},
	}
	out := captureStdout(t, func() { printOVALScanResults(results) })
	if !strings.Contains(out, "High (CVSS") || !strings.Contains(out, "nginx") {
		t.Errorf("a CVSS 8.1 finding should land in the High bucket, got:\n%s", out)
	}
	if !strings.Contains(out, "Medium (CVSS") || !strings.Contains(out, "bash") {
		t.Errorf("a CVSS 5.5 finding should land in the Medium bucket, got:\n%s", out)
	}
}
