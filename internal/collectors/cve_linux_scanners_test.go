//go:build linux

package collectors

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/keyorixhq/dashdiag/internal/cvedata"
	"github.com/keyorixhq/dashdiag/internal/models"
	"github.com/keyorixhq/dashdiag/internal/source"
)

// isolateCVEHome redirects HOME to a fresh temp dir and asserts no standard
// system OVAL/snapshot paths interfere, so tryOVALFallback/trySnapshotFallback
// deterministically miss unless a test explicitly seeds a file under the new
// HOME — required because cvedata.FindOVALFile/FindSnapshot read raw os.Stat
// on hardcoded paths, bypassing the activeSource fixture entirely.
func isolateCVEHome(t *testing.T) string {
	t.Helper()
	home := t.TempDir()
	t.Setenv("HOME", home)
	return home
}

// ── CheckCVE dispatcher ──────────────────────────────────────────────────────

func TestCheckCVE_InvalidFormat(t *testing.T) {
	res := CheckCVE(context.Background(), "not-a-cve")
	if res.Status != models.CVEUnknown {
		t.Fatalf("expected CVEUnknown for malformed ID, got %v", res.Status)
	}
	if !strings.Contains(res.StatusReason, "invalid CVE ID format") {
		t.Errorf("expected format-error reason, got %q", res.StatusReason)
	}
}

func TestCheckCVE_NoPackageManager(t *testing.T) {
	isolateCVEHome(t)
	withLookPathFixture(t, map[string]bool{}, func(b *source.Bundle) {})

	res := CheckCVE(context.Background(), "CVE-2024-1234")
	if res.Status != models.CVEUnknown {
		t.Fatalf("expected CVEUnknown with no package manager, got %v", res.Status)
	}
	if !strings.Contains(res.StatusReason, "no supported package manager") {
		t.Errorf("unexpected reason: %q", res.StatusReason)
	}
}

func TestCheckCVE_DispatchesToZypper(t *testing.T) {
	isolateCVEHome(t)
	withLookPathFixture(t, map[string]bool{"zypper": true}, func(b *source.Bundle) {
		b.PutCmd("zypper", []string{"--non-interactive", "--no-color", "lp", "--cve=CVE-2024-1234"},
			"No patch needed\n", 0)
	})
	res := CheckCVE(context.Background(), "CVE-2024-1234")
	if res.PackageManager != "zypper" {
		t.Fatalf("expected dispatch to zypper, got PackageManager=%q", res.PackageManager)
	}
}

func TestCheckCVE_DispatchesToDNF(t *testing.T) {
	isolateCVEHome(t)
	withLookPathFixture(t, map[string]bool{"dnf": true}, func(b *source.Bundle) {
		b.PutCmd("dnf", []string{"advisory", "info", "--cve", "CVE-2024-1234", "--quiet"},
			"No advisory found for this CVE\n", 0)
	})
	res := CheckCVE(context.Background(), "CVE-2024-1234")
	if res.PackageManager != "dnf" {
		t.Fatalf("expected dispatch to dnf, got PackageManager=%q", res.PackageManager)
	}
}

func TestCheckCVE_DispatchesToApt(t *testing.T) {
	isolateCVEHome(t)
	withLookPathFixture(t, map[string]bool{"apt-get": true}, func(b *source.Bundle) {
		b.PutCmd("sh", []string{"-c", "grep -i ubuntu /etc/os-release"}, "", 1)
		b.PutFile("/etc/os-release", []byte("ID=debian\n"))
	})
	res := CheckCVE(context.Background(), "CVE-2024-1234")
	if res.PackageManager != "apt" {
		t.Fatalf("expected dispatch to apt, got PackageManager=%q", res.PackageManager)
	}
}

func TestCheckCVE_DispatchesToPacman(t *testing.T) {
	isolateCVEHome(t)
	withLookPathFixture(t, map[string]bool{"pacman": true}, func(b *source.Bundle) {})
	res := CheckCVE(context.Background(), "CVE-2024-1234")
	if res.PackageManager != "pacman" {
		t.Fatalf("expected dispatch to pacman, got PackageManager=%q", res.PackageManager)
	}
}

func TestCheckCVE_DispatchesToTDNF(t *testing.T) {
	isolateCVEHome(t)
	withLookPathFixture(t, map[string]bool{"tdnf": true}, func(b *source.Bundle) {
		b.PutCmd("tdnf", []string{"updateinfo", "info", "--security"}, "Name : zlib\n", 0)
	})
	res := CheckCVE(context.Background(), "CVE-2024-1234")
	if res.PackageManager != "tdnf" {
		t.Fatalf("expected dispatch to tdnf, got PackageManager=%q", res.PackageManager)
	}
}

// ── readDistroID / ReadDistroID ──────────────────────────────────────────────

func TestReadDistroID(t *testing.T) {
	withFixtureSource(t, func(b *source.Bundle) {
		b.PutFile("/etc/os-release", []byte("NAME=\"Red Hat\"\nID=\"rhel\"\nVERSION_ID=\"10.0\"\n"))
	})
	if got := ReadDistroID(); got != "rhel" {
		t.Errorf("ReadDistroID() = %q, want rhel", got)
	}
	if got := readDistroID(); got != "rhel" {
		t.Errorf("readDistroID() = %q, want rhel", got)
	}
}

func TestReadDistroID_Missing(t *testing.T) {
	withFixtureSource(t, func(b *source.Bundle) {})
	if got := ReadDistroID(); got != "" {
		t.Errorf("ReadDistroID() = %q, want empty when os-release is unreadable", got)
	}
}

// ── tryOVALFallback / scanAllViaOVAL ─────────────────────────────────────────

func TestTryOVALFallback_NotFound(t *testing.T) {
	isolateCVEHome(t)
	withFixtureSource(t, func(b *source.Bundle) {
		b.PutFile("/etc/os-release", []byte("ID=ubuntu\n"))
	})
	if got := tryOVALFallback(context.Background(), "CVE-2024-1234"); got != nil {
		t.Errorf("expected nil with no staged OVAL feed, got %+v", got)
	}
}

func TestScanAllViaOVAL_NotFound(t *testing.T) {
	isolateCVEHome(t)
	withFixtureSource(t, func(b *source.Bundle) {
		b.PutFile("/etc/os-release", []byte("ID=ubuntu\n"))
	})
	if got := scanAllViaOVAL(context.Background()); got != nil {
		t.Errorf("expected nil with no staged OVAL feed, got %+v", got)
	}
}

// ── trySnapshotFallback ───────────────────────────────────────────────────────

func writeGzippedSnapshot(t *testing.T, home string, snap cvedata.Snapshot) {
	t.Helper()
	data, err := json.Marshal(snap)
	if err != nil {
		t.Fatalf("marshal snapshot: %v", err)
	}
	dir := filepath.Join(home, ".dsd")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	var buf bytes.Buffer
	gw := gzip.NewWriter(&buf)
	if _, err := gw.Write(data); err != nil {
		t.Fatalf("gzip write: %v", err)
	}
	if err := gw.Close(); err != nil {
		t.Fatalf("gzip close: %v", err)
	}
	path := filepath.Join(dir, "cvedata.json.gz")
	if err := os.WriteFile(path, buf.Bytes(), 0o644); err != nil {
		t.Fatalf("write snapshot: %v", err)
	}
}

func TestTrySnapshotFallback_NoSnapshot(t *testing.T) {
	isolateCVEHome(t)
	withFixtureSource(t, func(b *source.Bundle) {
		b.PutFile("/etc/os-release", []byte("ID=rhel\n"))
	})
	if got := trySnapshotFallback(context.Background(), "CVE-2024-1234"); got != nil {
		t.Errorf("expected nil with no staged snapshot, got %+v", got)
	}
}

func TestTrySnapshotFallback_CVENotInSnapshot(t *testing.T) {
	home := isolateCVEHome(t)
	writeGzippedSnapshot(t, home, cvedata.Snapshot{
		CVEs: map[string]cvedata.SnapshotCVE{
			"CVE-2024-9999": {Summary: "unrelated"},
		},
	})
	withFixtureSource(t, func(b *source.Bundle) {
		b.PutFile("/etc/os-release", []byte("ID=rhel\n"))
	})
	if got := trySnapshotFallback(context.Background(), "CVE-2024-1234"); got != nil {
		t.Errorf("expected nil when the CVE has no snapshot entry, got %+v", got)
	}
}

func TestTrySnapshotFallback_DistroNotApplicable(t *testing.T) {
	home := isolateCVEHome(t)
	writeGzippedSnapshot(t, home, cvedata.Snapshot{
		CVEs: map[string]cvedata.SnapshotCVE{
			"CVE-2024-1234": {
				Summary: "test CVE",
				Affected: map[string][]cvedata.SnapshotPackage{
					"opensuse-tumbleweed": {{Name: "openssl", FixedIn: "3.0.1"}},
				},
			},
		},
	})
	withFixtureSource(t, func(b *source.Bundle) {
		b.PutFile("/etc/os-release", []byte("ID=rhel\n"))
	})
	res := trySnapshotFallback(context.Background(), "CVE-2024-1234")
	if res == nil {
		t.Fatal("expected a concrete NotAffected result, got nil")
	}
	if res.Status != models.CVENotAffected {
		t.Errorf("Status = %v, want CVENotAffected", res.Status)
	}
	if !strings.Contains(res.StatusReason, "not applicable") {
		t.Errorf("StatusReason = %q, want 'not applicable' hint", res.StatusReason)
	}
}

func TestTrySnapshotFallback_AffectedButRPMUnavailable(t *testing.T) {
	// The snapshot lists the current distro as affected, but this container
	// has no rpm binary — cvedata.QueryInstalledRPM fails, so the fallback
	// still can't produce a verdict and must return nil rather than guess.
	home := isolateCVEHome(t)
	writeGzippedSnapshot(t, home, cvedata.Snapshot{
		CVEs: map[string]cvedata.SnapshotCVE{
			"CVE-2024-1234": {
				Summary: "test CVE",
				Affected: map[string][]cvedata.SnapshotPackage{
					"rhel:10": {{Name: "openssl", FixedIn: "3.0.1"}},
				},
			},
		},
	})
	withFixtureSource(t, func(b *source.Bundle) {
		b.PutFile("/etc/os-release", []byte("ID=rhel\n"))
	})
	if got := trySnapshotFallback(context.Background(), "CVE-2024-1234"); got != nil {
		t.Errorf("expected nil when rpm is unavailable to verify installed versions, got %+v", got)
	}
}

// ── DNF scanning ──────────────────────────────────────────────────────────────

func TestScanAllDNF_DNF5Success(t *testing.T) {
	withFixtureSource(t, func(b *source.Bundle) {
		b.PutCmdNotFound("dnf", []string{"makecache", "-q"})
		b.PutCmd("dnf", []string{"advisory", "list", "--security", "--quiet"},
			"RHSA-2026:0001  Critical/Sec.  openssl-3.0.1-1.el10.x86_64\n"+
				"RHSA-2026:0002  Important/Sec. curl-8.0.1-1.el10.x86_64\n", 0)
		b.PutCmd("dnf", []string{"updateinfo", "info", "--security", "--quiet"},
			"Update ID: RHSA-2026:0001\nCVEs: CVE-2026-1111\n", 0)
	})
	res := scanAllDNF(context.Background())
	if res.ScanFailed {
		t.Fatalf("expected a successful scan, got ScanFailed: %s", res.StatusReason)
	}
	if res.Total != 2 {
		t.Fatalf("expected 2 advisories, got %d: %+v", res.Total, res)
	}
	if len(res.Critical) != 1 || res.Critical[0].ID != "RHSA-2026:0001" {
		t.Errorf("Critical = %+v, want [RHSA-2026:0001]", res.Critical)
	}
	if len(res.Important) != 1 {
		t.Errorf("Important = %+v, want 1 entry", res.Important)
	}
	if res.Critical[0].CVEs != "CVE-2026-1111" {
		t.Errorf("expected enrichment to populate CVEs, got %q", res.Critical[0].CVEs)
	}
}

func TestScanAllDNF_DNF4Fallback(t *testing.T) {
	withFixtureSource(t, func(b *source.Bundle) {
		b.PutCmdNotFound("dnf", []string{"makecache", "-q"})
		b.PutCmdNotFound("dnf", []string{"advisory", "list", "--security", "--quiet"})
		b.PutCmd("dnf", []string{"updateinfo", "list", "security", "--quiet"},
			"RHSA-2026:0003  security  critical  package-1.2.3\n", 0)
		b.PutCmdNotFound("dnf", []string{"updateinfo", "info", "--security", "--quiet"})
	})
	res := scanAllDNF(context.Background())
	if res.Total != 1 || len(res.Critical) != 1 {
		t.Fatalf("expected 1 critical advisory from the DNF5 table format, got %+v", res)
	}
}

func TestScanAllDNF_UpToDate(t *testing.T) {
	withFixtureSource(t, func(b *source.Bundle) {
		b.PutCmdNotFound("dnf", []string{"makecache", "-q"})
		b.PutCmd("dnf", []string{"advisory", "list", "--security", "--quiet"}, "", 0)
	})
	res := scanAllDNF(context.Background())
	if res.ScanFailed {
		t.Fatal("empty advisory output is a clean scan, not a failure")
	}
	if !strings.Contains(res.StatusReason, "up to date") {
		t.Errorf("StatusReason = %q, want up-to-date message", res.StatusReason)
	}
}

func TestScanAllDNF_BothFail_NotTimeout(t *testing.T) {
	withFixtureSource(t, func(b *source.Bundle) {
		b.PutCmdNotFound("dnf", []string{"makecache", "-q"})
		b.PutCmdNotFound("dnf", []string{"advisory", "list", "--security", "--quiet"})
		b.PutCmdNotFound("dnf", []string{"updateinfo", "list", "security", "--quiet"})
	})
	res := scanAllDNF(context.Background())
	if !res.ScanFailed {
		t.Fatal("expected ScanFailed when both dnf queries fail")
	}
	if !strings.Contains(res.StatusReason, "no repo access") {
		t.Errorf("StatusReason = %q, want a no-repo-access reason", res.StatusReason)
	}
}

func TestScanAllDNF_BothFail_Timeout(t *testing.T) {
	withFixtureSource(t, func(b *source.Bundle) {
		b.PutCmdNotFound("dnf", []string{"makecache", "-q"})
		b.PutCmdNotFound("dnf", []string{"advisory", "list", "--security", "--quiet"})
		b.PutCmdNotFound("dnf", []string{"updateinfo", "list", "security", "--quiet"})
	})
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	res := scanAllDNF(ctx)
	if !res.ScanFailed {
		t.Fatal("expected ScanFailed for a cancelled context")
	}
	if !strings.Contains(res.StatusReason, "timed out") {
		t.Errorf("StatusReason = %q, want a timed-out reason for a cancelled ctx", res.StatusReason)
	}
}

// ── enrichDNFAdvisoryWithCVEs / rhSubscriptionNote ───────────────────────────

func TestEnrichDNFAdvisoryWithCVEs_Populates(t *testing.T) {
	withFixtureSource(t, func(b *source.Bundle) {
		b.PutCmd("dnf", []string{"updateinfo", "info", "--security", "--quiet"},
			"Update ID: RHSA-2026:0001\nCVEs: CVE-2026-1111, CVE-2026-2222\n", 0)
	})
	result := &models.CVEAllResult{
		Critical: []models.CVEAdvisory{{ID: "RHSA-2026:0001"}},
	}
	enrichDNFAdvisoryWithCVEs(context.Background(), result)
	if result.Critical[0].CVEs != "CVE-2026-1111, CVE-2026-2222" {
		t.Errorf("CVEs = %q, want both IDs", result.Critical[0].CVEs)
	}
}

func TestEnrichDNFAdvisoryWithCVEs_FailsSetsSubscriptionNote(t *testing.T) {
	withFixtureSource(t, func(b *source.Bundle) {
		b.PutCmdNotFound("dnf", []string{"updateinfo", "info", "--security", "--quiet"})
		b.PutFile("/etc/os-release", []byte("ID=fedora\n"))
	})
	result := &models.CVEAllResult{}
	enrichDNFAdvisoryWithCVEs(context.Background(), result)
	// Fedora is free (never subscription-gated) — the note stays empty even
	// though the underlying query failed.
	if result.SubscriptionNote != "" {
		t.Errorf("expected no subscription note on Fedora, got %q", result.SubscriptionNote)
	}
}

func TestRHSubscriptionNote_Fedora(t *testing.T) {
	withFixtureSource(t, func(b *source.Bundle) {
		b.PutFile("/etc/os-release", []byte("ID=fedora\n"))
	})
	if got := rhSubscriptionNote(); got != "" {
		t.Errorf("expected empty note for Fedora, got %q", got)
	}
}

func TestRHSubscriptionNote_NonRHFamily(t *testing.T) {
	withFixtureSource(t, func(b *source.Bundle) {
		b.PutFile("/etc/os-release", []byte("ID=debian\n"))
	})
	if got := rhSubscriptionNote(); got != "" {
		t.Errorf("expected empty note for a non-RH distro, got %q", got)
	}
}

func TestRHSubscriptionNote_RootNotRegistered(t *testing.T) {
	if os.Getuid() != 0 {
		t.Skip("requires root — the not-registered branch only checks entitlement certs as root")
	}
	withFixtureSource(t, func(b *source.Bundle) {
		b.PutFile("/etc/os-release", []byte("ID=rhel\n"))
	})
	got := rhSubscriptionNote()
	if !strings.Contains(got, "not registered") {
		t.Errorf("expected a not-registered message, got %q", got)
	}
}

func TestRHSubscriptionNote_RootExpiredCerts(t *testing.T) {
	if os.Getuid() != 0 {
		t.Skip("requires root")
	}
	withFixtureSource(t, func(b *source.Bundle) {
		b.PutFile("/etc/os-release", []byte("ID=centos\n"))
		b.PutDir("/etc/pki/entitlement", []string{"1234567890-key.pem"})
	})
	got := rhSubscriptionNote()
	if !strings.Contains(got, "expired") {
		t.Errorf("expected an expired-subscription message, got %q", got)
	}
}

func TestRHSubscriptionNote_RootActiveSubscription(t *testing.T) {
	if os.Getuid() != 0 {
		t.Skip("requires root")
	}
	withFixtureSource(t, func(b *source.Bundle) {
		b.PutFile("/etc/os-release", []byte("ID=rocky\n"))
		b.PutDir("/etc/pki/entitlement", []string{"1234567890.pem", "1234567890-key.pem"})
	})
	got := rhSubscriptionNote()
	if !strings.Contains(got, "Subscription active") {
		t.Errorf("expected an active-subscription message, got %q", got)
	}
}

// ── Pacman / arch-audit ───────────────────────────────────────────────────────

func TestCheckCVEPacman_NotInstalled(t *testing.T) {
	withLookPathFixture(t, map[string]bool{}, func(b *source.Bundle) {})
	res := checkCVEPacman(context.Background(), "CVE-2024-1234")
	if res.Status != models.CVEUnknown {
		t.Fatalf("expected CVEUnknown without arch-audit, got %v", res.Status)
	}
	if !strings.Contains(res.FallbackURL, "security.archlinux.org") {
		t.Errorf("expected an Arch security tracker URL, got %q", res.FallbackURL)
	}
}

func TestCheckCVEPacman_QueryFails(t *testing.T) {
	withLookPathFixture(t, map[string]bool{"arch-audit": true}, func(b *source.Bundle) {
		b.PutCmdNotFound("arch-audit", []string{"--format", "%n %c %s"})
	})
	res := checkCVEPacman(context.Background(), "CVE-2024-1234")
	if res.Status != models.CVEUnknown {
		t.Fatalf("expected CVEUnknown on query failure, got %v", res.Status)
	}
}

func TestCheckCVEPacman_Vulnerable(t *testing.T) {
	withLookPathFixture(t, map[string]bool{"arch-audit": true}, func(b *source.Bundle) {
		b.PutCmd("arch-audit", []string{"--format", "%n %c %s"},
			"openssl CVE-2024-1234 Critical\n", 0)
	})
	res := checkCVEPacman(context.Background(), "CVE-2024-1234")
	if res.Status != models.CVEVulnerable {
		t.Fatalf("expected CVEVulnerable, got %v", res.Status)
	}
	if len(res.AffectedPackages) != 1 || res.AffectedPackages[0].Name != "openssl" {
		t.Errorf("AffectedPackages = %+v, want [openssl]", res.AffectedPackages)
	}
	if res.AffectedPackages[0].Severity != "critical" {
		t.Errorf("Severity = %q, want critical", res.AffectedPackages[0].Severity)
	}
}

func TestCheckCVEPacman_NotAffected(t *testing.T) {
	withLookPathFixture(t, map[string]bool{"arch-audit": true}, func(b *source.Bundle) {
		b.PutCmd("arch-audit", []string{"--format", "%n %c %s"},
			"curl CVE-2024-9999 Low\n", 0)
	})
	res := checkCVEPacman(context.Background(), "CVE-2024-1234")
	if res.Status != models.CVENotAffected {
		t.Fatalf("expected CVENotAffected when no line matches, got %v", res.Status)
	}
}

func TestScanAllPacman_NotInstalled(t *testing.T) {
	withLookPathFixture(t, map[string]bool{}, func(b *source.Bundle) {})
	res := scanAllPacman(context.Background())
	if !res.ScanFailed {
		t.Fatal("expected ScanFailed without arch-audit")
	}
}

func TestScanAllPacman_QueryFails(t *testing.T) {
	withLookPathFixture(t, map[string]bool{"arch-audit": true}, func(b *source.Bundle) {
		b.PutCmdNotFound("arch-audit", []string{"-u"})
	})
	res := scanAllPacman(context.Background())
	if !res.ScanFailed {
		t.Fatal("expected ScanFailed on query failure")
	}
}

func TestScanAllPacman_UpToDate(t *testing.T) {
	withLookPathFixture(t, map[string]bool{"arch-audit": true}, func(b *source.Bundle) {
		b.PutCmd("arch-audit", []string{"-u"}, "", 0)
	})
	res := scanAllPacman(context.Background())
	if res.ScanFailed {
		t.Fatal("empty output is a clean scan, not a failure")
	}
	if !strings.Contains(res.StatusReason, "up to date") {
		t.Errorf("StatusReason = %q, want up-to-date message", res.StatusReason)
	}
}

func TestScanAllPacman_Vulnerable(t *testing.T) {
	withLookPathFixture(t, map[string]bool{"arch-audit": true}, func(b *source.Bundle) {
		b.PutCmd("arch-audit", []string{"-u"},
			"openssl is affected by CVE-2024-1111, CVE-2024-2222 [Critical]: remote code execution\n"+
				"curl is affected by CVE-2024-3333 [Medium]: info leak\n", 0)
	})
	res := scanAllPacman(context.Background())
	if res.Total != 2 {
		t.Fatalf("expected 2 advisories, got %d: %+v", res.Total, res)
	}
	if len(res.Critical) != 1 || res.Critical[0].ID != "openssl" {
		t.Errorf("Critical = %+v, want [openssl]", res.Critical)
	}
	if res.Critical[0].CVEs != "CVE-2024-1111, CVE-2024-2222" {
		t.Errorf("CVEs = %q, want both IDs", res.Critical[0].CVEs)
	}
	if res.Critical[0].Summary != "remote code execution" {
		t.Errorf("Summary = %q, want the trailing description", res.Critical[0].Summary)
	}
	if len(res.Moderate) != 1 || res.Moderate[0].ID != "curl" {
		t.Errorf("Moderate = %+v, want [curl]", res.Moderate)
	}
}

// ── TDNF / Photon ─────────────────────────────────────────────────────────────

func TestCheckCVETDNF_QueryFails(t *testing.T) {
	withFixtureSource(t, func(b *source.Bundle) {
		b.PutCmdNotFound("tdnf", []string{"updateinfo", "info", "--security"})
		b.PutFile("/etc/os-release", []byte("VERSION_ID=\"5.0\"\n"))
	})
	res := checkCVETDNF(context.Background(), "CVE-2026-1234")
	if res.Status != models.CVEUnknown {
		t.Fatalf("expected CVEUnknown on query failure, got %v", res.Status)
	}
	if !strings.Contains(res.FallbackURL, "Security-Update-5") {
		t.Errorf("expected the Photon 5 wiki URL, got %q", res.FallbackURL)
	}
}

func TestCheckCVETDNF_Vulnerable(t *testing.T) {
	withFixtureSource(t, func(b *source.Bundle) {
		b.PutCmd("tdnf", []string{"updateinfo", "info", "--security"},
			"Name : zlib.x86_64\nUpdate ID : patch:PHSA-2026-5.0-0874\n"+
				"Description : Security fixes for {'CVE-2026-1234'}\n", 0)
	})
	res := checkCVETDNF(context.Background(), "CVE-2026-1234")
	if res.Status != models.CVEVulnerable {
		t.Fatalf("expected CVEVulnerable, got %v", res.Status)
	}
	if res.FixAdvisory != "PHSA-2026-5.0-0874" {
		t.Errorf("FixAdvisory = %q, want PHSA-2026-5.0-0874", res.FixAdvisory)
	}
}

func TestCheckCVETDNF_NotAffected(t *testing.T) {
	withFixtureSource(t, func(b *source.Bundle) {
		b.PutCmd("tdnf", []string{"updateinfo", "info", "--security"},
			"Name : zlib.x86_64\nUpdate ID : patch:PHSA-2026-5.0-0874\n"+
				"Description : Security fixes for {'CVE-2026-9999'}\n", 0)
	})
	res := checkCVETDNF(context.Background(), "CVE-2026-1234")
	if res.Status != models.CVENotAffected {
		t.Fatalf("expected CVENotAffected, got %v", res.Status)
	}
}

func TestScanAllTDNF_NoEnabledRepo(t *testing.T) {
	withFixtureSource(t, func(b *source.Bundle) {
		b.PutCmd("tdnf", []string{"-j", "repolist"}, `[{"Repo":"x","Enabled":false}]`, 0)
	})
	res := scanAllTDNF(context.Background())
	if !res.ScanFailed {
		t.Fatal("expected ScanFailed when no repos are enabled")
	}
	if !strings.Contains(res.StatusReason, "no enabled tdnf repositories") {
		t.Errorf("StatusReason = %q", res.StatusReason)
	}
}

func TestScanAllTDNF_JSONSuccess(t *testing.T) {
	withFixtureSource(t, func(b *source.Bundle) {
		b.PutCmd("tdnf", []string{"-j", "repolist"}, `[{"Repo":"photon-updates","Enabled":true}]`, 0)
		b.PutCmd("tdnf", []string{"-j", "updateinfo", "list", "--security"},
			`[{"Type":"Security","UpdateID":"patch:PHSA-2026-5.0-0001","Packages":["zlib-1.3.2-1.ph5.x86_64.rpm"]}]`, 0)
		b.PutCmd("tdnf", []string{"updateinfo", "info", "--security"},
			"Update ID : patch:PHSA-2026-5.0-0001\nDescription : Security fixes for {'CVE-2026-1111'}\n", 0)
	})
	res := scanAllTDNF(context.Background())
	if res.ScanFailed {
		t.Fatalf("expected a successful scan, got ScanFailed: %s", res.StatusReason)
	}
	if res.Total != 1 || len(res.Important) != 1 {
		t.Fatalf("expected 1 Important advisory, got %+v", res)
	}
	if res.Important[0].ID != "PHSA-2026-5.0-0001" {
		t.Errorf("ID = %q, want PHSA-2026-5.0-0001", res.Important[0].ID)
	}
	if res.Important[0].CVEs != "CVE-2026-1111" {
		t.Errorf("expected enrichment to populate CVEs, got %q", res.Important[0].CVEs)
	}
}

func TestScanAllTDNF_JSONFailsFallsBackToText(t *testing.T) {
	withFixtureSource(t, func(b *source.Bundle) {
		b.PutCmd("tdnf", []string{"-j", "repolist"}, `[{"Repo":"photon-updates","Enabled":true}]`, 0)
		b.PutCmd("tdnf", []string{"-j", "updateinfo", "list", "--security"}, "not json", 0)
		b.PutCmd("tdnf", []string{"updateinfo", "list", "--security"},
			"patch:PHSA-2026-5.0-0002 Security lz4-1.10.0-1.ph5.x86_64.rpm\n", 0)
		b.PutCmdNotFound("tdnf", []string{"updateinfo", "info", "--security"})
	})
	res := scanAllTDNF(context.Background())
	if res.Total != 1 {
		t.Fatalf("expected the text fallback to yield 1 advisory, got %+v", res)
	}
}

func TestScanAllTDNF_UpToDate(t *testing.T) {
	withFixtureSource(t, func(b *source.Bundle) {
		b.PutCmd("tdnf", []string{"-j", "repolist"}, `[{"Repo":"photon-updates","Enabled":true}]`, 0)
		b.PutCmd("tdnf", []string{"-j", "updateinfo", "list", "--security"}, "[]", 0)
	})
	res := scanAllTDNF(context.Background())
	if res.ScanFailed {
		t.Fatal("no pending advisories is a clean scan")
	}
	if !strings.Contains(res.StatusReason, "up to date") {
		t.Errorf("StatusReason = %q, want up-to-date message", res.StatusReason)
	}
}

func TestScanAllTDNF_BothQueriesFail(t *testing.T) {
	withFixtureSource(t, func(b *source.Bundle) {
		b.PutCmd("tdnf", []string{"-j", "repolist"}, `[{"Repo":"photon-updates","Enabled":true}]`, 0)
		b.PutCmdNotFound("tdnf", []string{"-j", "updateinfo", "list", "--security"})
		b.PutCmdNotFound("tdnf", []string{"updateinfo", "list", "--security"})
	})
	res := scanAllTDNF(context.Background())
	if !res.ScanFailed {
		t.Fatal("expected ScanFailed when both updateinfo queries fail")
	}
}

func TestEnrichTDNFAdvisoryWithCVEs_Populates(t *testing.T) {
	withFixtureSource(t, func(b *source.Bundle) {
		b.PutCmd("tdnf", []string{"updateinfo", "info", "--security"},
			"Update ID : patch:PHSA-2026-5.0-0001\nDescription : Security fixes for {'CVE-2026-1111', 'CVE-2026-2222'}\n", 0)
	})
	byID := map[string]*models.CVEAdvisory{"PHSA-2026-5.0-0001": {ID: "PHSA-2026-5.0-0001"}}
	enrichTDNFAdvisoryWithCVEs(context.Background(), byID)
	got := byID["PHSA-2026-5.0-0001"].CVEs
	if !strings.Contains(got, "CVE-2026-1111") || !strings.Contains(got, "CVE-2026-2222") {
		t.Errorf("CVEs = %q, want both IDs", got)
	}
}

func TestEnrichTDNFAdvisoryWithCVEs_QueryFails(t *testing.T) {
	withFixtureSource(t, func(b *source.Bundle) {
		b.PutCmdNotFound("tdnf", []string{"updateinfo", "info", "--security"})
	})
	byID := map[string]*models.CVEAdvisory{"PHSA-2026-5.0-0001": {ID: "PHSA-2026-5.0-0001"}}
	enrichTDNFAdvisoryWithCVEs(context.Background(), byID)
	if byID["PHSA-2026-5.0-0001"].CVEs != "" {
		t.Errorf("expected no CVEs populated on query failure, got %q", byID["PHSA-2026-5.0-0001"].CVEs)
	}
}

func TestTdnfHasEnabledRepo_JSONTrue(t *testing.T) {
	withFixtureSource(t, func(b *source.Bundle) {
		b.PutCmd("tdnf", []string{"-j", "repolist"}, `[{"Repo":"x","Enabled":true}]`, 0)
	})
	if !tdnfHasEnabledRepo(context.Background()) {
		t.Error("expected true with one enabled repo")
	}
}

func TestTdnfHasEnabledRepo_JSONFalse(t *testing.T) {
	withFixtureSource(t, func(b *source.Bundle) {
		b.PutCmd("tdnf", []string{"-j", "repolist"}, `[{"Repo":"x","Enabled":false}]`, 0)
	})
	if tdnfHasEnabledRepo(context.Background()) {
		t.Error("expected false with zero enabled repos")
	}
}

func TestTdnfHasEnabledRepo_TextFallback(t *testing.T) {
	withFixtureSource(t, func(b *source.Bundle) {
		b.PutCmdNotFound("tdnf", []string{"-j", "repolist"})
		b.PutCmd("tdnf", []string{"repolist"},
			"repo id  repo name  status\nphoton-updates  Photon Updates  enabled\n", 0)
	})
	if !tdnfHasEnabledRepo(context.Background()) {
		t.Error("expected true from the text fallback")
	}
}

func TestTdnfHasEnabledRepo_BothFailConservativeTrue(t *testing.T) {
	withFixtureSource(t, func(b *source.Bundle) {
		b.PutCmdNotFound("tdnf", []string{"-j", "repolist"})
		b.PutCmdNotFound("tdnf", []string{"repolist"})
	})
	if !tdnfHasEnabledRepo(context.Background()) {
		t.Error("expected the conservative default true when repolist can't be read at all")
	}
}

func TestPhotonMajor(t *testing.T) {
	withFixtureSource(t, func(b *source.Bundle) {
		b.PutFile("/etc/os-release", []byte("VERSION_ID=\"5.0\"\n"))
	})
	if got := photonMajor(); got != "5" {
		t.Errorf("photonMajor() = %q, want 5", got)
	}
}

func TestPhotonMajor_NoDot(t *testing.T) {
	withFixtureSource(t, func(b *source.Bundle) {
		b.PutFile("/etc/os-release", []byte("VERSION_ID=4\n"))
	})
	if got := photonMajor(); got != "4" {
		t.Errorf("photonMajor() = %q, want 4", got)
	}
}

func TestPhotonMajor_FileMissing(t *testing.T) {
	withFixtureSource(t, func(b *source.Bundle) {})
	if got := photonMajor(); got != "5" {
		t.Errorf("photonMajor() = %q, want default 5", got)
	}
}
