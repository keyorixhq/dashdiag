//go:build linux

package collectors

import (
	"context"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/keyorixhq/dashdiag/internal/models"
	"github.com/keyorixhq/dashdiag/internal/source"
)

// ── Identity / Collect orchestration ─────────────────────────────────────────

func TestPackagesCollectorIdentity(t *testing.T) {
	c := NewPackagesCollector()
	if c.Name() != "Packages" {
		t.Errorf("Name() = %q, want Packages", c.Name())
	}
	if c.Deep {
		t.Error("NewPackagesCollector: expected Deep=false")
	}
	if c.Timeout() != 50*time.Second {
		t.Errorf("Timeout() = %v, want 50s", c.Timeout())
	}
	dc := NewPackagesDeepCollector()
	if !dc.Deep {
		t.Error("NewPackagesDeepCollector: expected Deep=true")
	}
	if dc.Timeout() != 65*time.Second {
		t.Errorf("deep Timeout() = %v, want 65s", dc.Timeout())
	}
}

func TestPackagesCollector_Collect_NoPackageManager(t *testing.T) {
	withFixtureSource(t, func(b *source.Bundle) {
		b.PutCmdNotFound("zypper", []string{"--version"})
		b.PutCmdNotFound("dnf", []string{"--version"})
		b.PutCmdNotFound("apt-get", []string{"--version"})
		b.PutCmdNotFound("tdnf", []string{"--version"})
	})
	c := NewPackagesCollector()
	res, err := c.Collect(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	info := res.(*models.PackagesInfo)
	if info.PackageManager != "unknown" {
		t.Errorf("PackageManager = %q, want unknown", info.PackageManager)
	}
}

func TestPackagesCollector_Collect_DNFHappyPath(t *testing.T) {
	withFixtureSource(t, func(b *source.Bundle) {
		b.PutCmd("zypper", []string{"--version"}, "", 1)
		b.PutCmdNotFound("zypper", []string{"--version"})
		b.PutCmd("dnf", []string{"--version"}, "dnf version 5.0\n", 0)
		b.PutCmdNotFound("rpm", []string{"-q", "rpm"}) // rpmDBHealth: no rpm tool -> checked=false
		b.PutCmdNotFound("dnf", []string{"makecache", "-q"})
		b.PutCmd("dnf", []string{"repolist", "--enabled", "-q"}, "repo-id  repo-name\nbaseos   BaseOS\n", 0)
		b.PutCmd("dnf", []string{"advisory", "list", "--security", "--quiet"},
			"RHSA-2026:0001  Critical/Sec.  openssl-3.0.1-1.el10.x86_64\n", 0)
	})
	c := NewPackagesCollector()
	res, err := c.Collect(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	info := res.(*models.PackagesInfo)
	if info.PackageManager != "dnf" {
		t.Fatalf("PackageManager = %q, want dnf", info.PackageManager)
	}
	if info.SecurityUpdates != 1 {
		t.Errorf("SecurityUpdates = %d, want 1", info.SecurityUpdates)
	}
	if info.Integrity != nil {
		t.Error("non-deep Collect must not populate Integrity")
	}
}

func TestPackagesCollector_Collect_DeepPopulatesIntegrity(t *testing.T) {
	withFixtureSource(t, func(b *source.Bundle) {
		b.PutCmd("zypper", []string{"--version"}, "", 1)
		b.PutCmd("dnf", []string{"--version"}, "dnf version 5.0\n", 0)
		b.PutCmdNotFound("rpm", []string{"-q", "rpm"})
		b.PutCmd("dnf", []string{"advisory", "list", "--security", "--quiet"}, "", 0)
		b.PutCmdNotFound("dnf", []string{"check", "--quiet"})
		b.PutCmdNotFound("rpm", []string{"--verify", "bash", "coreutils", "systemd", "glibc", "openssl-libs"})
		b.PutCmdNotFound("ldconfig", []string{"-p"})
	})
	c := NewPackagesDeepCollector()
	res, err := c.Collect(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	info := res.(*models.PackagesInfo)
	if info.Integrity == nil {
		t.Fatal("deep Collect must populate Integrity")
	}
	if info.Integrity.LdconfigOK {
		t.Error("expected LdconfigOK=false when ldconfig is not found")
	}
}

// TestPackagesCollector_Collect_ZypperDispatch guards Collect()'s zypper
// switch case: detectPackageManager finding zypper first must route through
// collectZypper, not just be exercised indirectly via collectZypper's own
// unit tests.
func TestPackagesCollector_Collect_ZypperDispatch(t *testing.T) {
	withFixtureSource(t, func(b *source.Bundle) {
		b.PutCmd("zypper", []string{"--version"}, "zypper 1.14.0\n", 0)
		b.PutCmdNotFound("rpm", []string{"-q", "rpm"}) // rpmDBHealth: no rpm tool -> checked=false
		b.PutCmd("zypper", []string{"--non-interactive", "--no-color", "list-patches", "--category", "security"},
			"Repository | Name | Category | Severity | Interactive | Status | Summary\n"+
				"repo-oss | SUSE-2026-1 | security | critical | --- | needed | openssl fix\n", 0)
		b.PutCmd("zypper", []string{"--non-interactive", "--no-color", "repos"},
			"# | Alias | Name | Enabled\n1 | repo-oss | Update repository | Yes\n", 0)
		b.PutCmdNotFound("zypper", []string{"--non-interactive", "--no-color", "search", "--installed-only", grubPackageForArch()})
		b.PutCmdNotFound("SUSEConnect", []string{"--status"})
		b.PutCmdNotFound("uname", []string{"-r"})
	})
	c := NewPackagesCollector()
	res, err := c.Collect(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	info := res.(*models.PackagesInfo)
	if info.PackageManager != "zypper" {
		t.Fatalf("PackageManager = %q, want zypper", info.PackageManager)
	}
	if info.SecurityUpdates != 1 || info.CriticalUpdates != 1 {
		t.Errorf("expected 1 security/1 critical update, got %+v", info)
	}
}

// TestPackagesCollector_Collect_APTDispatch guards Collect()'s apt switch
// case end to end (detectPackageManager -> collectAPT -> the folded result).
func TestPackagesCollector_Collect_APTDispatch(t *testing.T) {
	withFixtureSource(t, func(b *source.Bundle) {
		b.PutCmd("zypper", []string{"--version"}, "", 1)
		b.PutCmd("dnf", []string{"--version"}, "", 1)
		b.PutCmd("apt-get", []string{"--version"}, "apt 2.6.1\n", 0)
		b.PutCmd("dpkg", []string{"--audit"}, "", 0) // aptDBHealth: clean
		b.PutFile("/etc/apt/sources.list", []byte(
			"deb http://security.debian.org/debian-security bookworm-security main\n"))
		b.PutCmd("apt-get", []string{"-s", "upgrade"},
			"Inst openssl [3.0.9-1] (3.0.11-1~deb12u2 Debian-Security:12/stable-security [amd64])\n"+
				"0 upgraded, 0 newly installed\n", 0)
		b.PutCmdNotFound("pro", []string{"security-status", "--format", "json"})
	})
	c := NewPackagesCollector()
	res, err := c.Collect(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	info := res.(*models.PackagesInfo)
	if info.PackageManager != "apt" {
		t.Fatalf("PackageManager = %q, want apt", info.PackageManager)
	}
	if info.SecurityUpdates != 1 || info.CriticalUpdates != 1 {
		t.Errorf("expected 1 security/1 critical update, got %+v", info)
	}
}

// TestPackagesCollector_Collect_TDNFDispatch guards Collect()'s tdnf switch
// case (Photon OS) end to end.
func TestPackagesCollector_Collect_TDNFDispatch(t *testing.T) {
	withFixtureSource(t, func(b *source.Bundle) {
		b.PutCmd("zypper", []string{"--version"}, "", 1)
		b.PutCmd("dnf", []string{"--version"}, "", 1)
		b.PutCmd("apt-get", []string{"--version"}, "", 1)
		b.PutCmd("tdnf", []string{"--version"}, "tdnf version 3.0\n", 0)
		b.PutCmdNotFound("rpm", []string{"-q", "rpm"}) // rpmDBHealth: no rpm tool -> checked=false
		b.PutCmd("tdnf", []string{"-j", "repolist"}, `[{"Repo":"photon-updates","Enabled":true}]`, 0)
		b.PutCmd("tdnf", []string{"-j", "updateinfo", "list", "--security"},
			`[{"Type":"Security","UpdateID":"patch:PHSA-2026-5.0-0001","Packages":["zlib-1.3.2-1.ph5.x86_64.rpm"]}]`, 0)
	})
	c := NewPackagesCollector()
	res, err := c.Collect(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	info := res.(*models.PackagesInfo)
	if info.PackageManager != "tdnf" {
		t.Fatalf("PackageManager = %q, want tdnf", info.PackageManager)
	}
	if info.SecurityUpdates != 1 {
		t.Errorf("expected 1 security update, got %+v", info)
	}
}

// ── collectAPTKali ────────────────────────────────────────────────────────────

// TestCollectAPTKali_AptGetFails drives the "apt-get -s upgrade unavailable"
// branch — the result must still be returned (no error) with a StatusReason,
// not a hard failure.
func TestCollectAPTKali_AptGetFails(t *testing.T) {
	withFixtureSource(t, func(b *source.Bundle) {
		b.PutCmdNotFound("apt-get", []string{"-s", "upgrade"})
	})
	info := &models.PackagesInfo{Checked: true, PackageManager: "apt"}
	got, err := collectAPTKali(context.Background(), info)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got.StatusReason != "apt-get unavailable" {
		t.Errorf("StatusReason = %q, want %q", got.StatusReason, "apt-get unavailable")
	}
	if !got.HasSecurityRepo {
		t.Error("expected HasSecurityRepo=true (kali-rolling is the security channel)")
	}
}

// TestCollectAPTKali_MixedSeverityAndMalformedLine covers: a short "Inst" line
// (< 2 fields) is skipped, and a non-critical package name is counted as
// ImportantUpdates rather than CriticalUpdates.
func TestCollectAPTKali_MixedSeverityAndMalformedLine(t *testing.T) {
	withFixtureSource(t, func(b *source.Bundle) {
		b.PutCmd("apt-get", []string{"-s", "upgrade"},
			"Inst\n"+ // malformed: fields[1] out of range, must be skipped
				"Inst some-random-package [1.0] (1.1 Debian:kali-rolling [amd64])\n"+
				"Inst openssl [3.0.1] (3.0.2 Debian:kali-rolling [amd64])\n", 0)
	})
	info := &models.PackagesInfo{Checked: true, PackageManager: "apt"}
	got, err := collectAPTKali(context.Background(), info)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got.CriticalUpdates != 1 {
		t.Errorf("CriticalUpdates = %d, want 1 (openssl)", got.CriticalUpdates)
	}
	if got.ImportantUpdates != 1 {
		t.Errorf("ImportantUpdates = %d, want 1 (some-random-package)", got.ImportantUpdates)
	}
	if got.SecurityUpdates != 2 {
		t.Errorf("SecurityUpdates = %d, want 2 (malformed line excluded)", got.SecurityUpdates)
	}
}

// ── detectPackageManager ──────────────────────────────────────────────────────

func TestDetectPackageManager(t *testing.T) {
	cases := []struct {
		name string
		seed func(b *source.Bundle)
		want string
	}{
		{"zypper", func(b *source.Bundle) {
			b.PutCmd("zypper", []string{"--version"}, "zypper 1.14\n", 0)
		}, "zypper"},
		{"dnf", func(b *source.Bundle) {
			b.PutCmdNotFound("zypper", []string{"--version"})
			b.PutCmd("dnf", []string{"--version"}, "dnf 5.0\n", 0)
		}, "dnf"},
		{"apt", func(b *source.Bundle) {
			b.PutCmdNotFound("zypper", []string{"--version"})
			b.PutCmdNotFound("dnf", []string{"--version"})
			b.PutCmd("apt-get", []string{"--version"}, "apt 2.6\n", 0)
		}, "apt"},
		{"tdnf", func(b *source.Bundle) {
			b.PutCmdNotFound("zypper", []string{"--version"})
			b.PutCmdNotFound("dnf", []string{"--version"})
			b.PutCmdNotFound("apt-get", []string{"--version"})
			b.PutCmd("tdnf", []string{"--version"}, "tdnf version 3.5.0\n", 0)
		}, "tdnf"},
		{"none", func(b *source.Bundle) {
			b.PutCmdNotFound("zypper", []string{"--version"})
			b.PutCmdNotFound("dnf", []string{"--version"})
			b.PutCmdNotFound("apt-get", []string{"--version"})
			b.PutCmdNotFound("tdnf", []string{"--version"})
		}, ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			withFixtureSource(t, tc.seed)
			if got := detectPackageManager(context.Background()); got != tc.want {
				t.Errorf("detectPackageManager() = %q, want %q", got, tc.want)
			}
		})
	}
}

// ── pkgDBHealth dispatcher ────────────────────────────────────────────────────

func TestPkgDBHealth_Apt(t *testing.T) {
	withFixtureSource(t, func(b *source.Bundle) {
		b.PutCmd("dpkg", []string{"--audit"}, "", 0)
	})
	checked, blocked, _, _ := pkgDBHealth(context.Background(), "apt")
	if !checked || blocked {
		t.Errorf("expected checked=true blocked=false for a clean apt DB, got checked=%v blocked=%v", checked, blocked)
	}
}

func TestPkgDBHealth_RPMFamily(t *testing.T) {
	for _, pm := range []string{"dnf", "yum", "zypper", "tdnf"} {
		t.Run(pm, func(t *testing.T) {
			withLookPathFixture(t, map[string]bool{"rpm": true}, func(b *source.Bundle) {
				b.PutCmd("rpm", []string{"-q", "rpm"}, "rpm-4.18.0-1\n", 0)
			})
			checked, blocked, _, _ := pkgDBHealth(context.Background(), pm)
			if !checked || blocked {
				t.Errorf("%s: expected checked=true blocked=false, got checked=%v blocked=%v", pm, checked, blocked)
			}
		})
	}
}

func TestPkgDBHealth_UnknownManager(t *testing.T) {
	withFixtureSource(t, func(b *source.Bundle) {})
	checked, blocked, reason, fix := pkgDBHealth(context.Background(), "brew")
	if checked || blocked || reason != "" || fix != "" {
		t.Errorf("expected all-zero for an unrecognised manager, got checked=%v blocked=%v reason=%q fix=%q",
			checked, blocked, reason, fix)
	}
}

// ── collectTDNF ───────────────────────────────────────────────────────────────

func TestCollectTDNF_NoEnabledRepo(t *testing.T) {
	withFixtureSource(t, func(b *source.Bundle) {
		b.PutCmd("tdnf", []string{"-j", "repolist"}, `[{"Repo":"x","Enabled":false}]`, 0)
	})
	info, err := collectTDNF(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if info.Status != "query-failed" {
		t.Errorf("Status = %q, want query-failed", info.Status)
	}
}

func TestCollectTDNF_HappyPath(t *testing.T) {
	withFixtureSource(t, func(b *source.Bundle) {
		b.PutCmd("tdnf", []string{"-j", "repolist"}, `[{"Repo":"photon-updates","Enabled":true}]`, 0)
		b.PutCmd("tdnf", []string{"-j", "updateinfo", "list", "--security"},
			`[{"Type":"Security","UpdateID":"patch:PHSA-2026-5.0-0001","Packages":["zlib-1.3.2-1.ph5.x86_64.rpm"]}]`, 0)
	})
	info, err := collectTDNF(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if info.SecurityUpdates != 1 || info.ImportantUpdates != 1 {
		t.Fatalf("expected 1 security/important update, got %+v", info)
	}
	if info.Updates[0].Name != "zlib-1.3.2-1.ph5.x86_64" {
		t.Errorf("Updates[0].Name = %q, want zlib-1.3.2-1.ph5.x86_64 (.rpm suffix trimmed)", info.Updates[0].Name)
	}
}

func TestCollectTDNF_BothQueriesFail(t *testing.T) {
	withFixtureSource(t, func(b *source.Bundle) {
		b.PutCmd("tdnf", []string{"-j", "repolist"}, `[{"Repo":"photon-updates","Enabled":true}]`, 0)
		b.PutCmdNotFound("tdnf", []string{"-j", "updateinfo", "list", "--security"})
		b.PutCmdNotFound("tdnf", []string{"updateinfo", "list", "--security"})
	})
	info, err := collectTDNF(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if info.Status != "query-failed" {
		t.Errorf("Status = %q, want query-failed", info.Status)
	}
}

// ── collectZypper ─────────────────────────────────────────────────────────────

func TestCollectZypper_HappyPath(t *testing.T) {
	withFixtureSource(t, func(b *source.Bundle) {
		b.PutCmd("zypper", []string{"--non-interactive", "--no-color", "list-patches", "--category", "security"},
			"Repository | Name | Category | Severity | Interactive | Status | Summary\n"+
				"repo-oss | SUSE-2026-1 | security | critical | --- | needed | openssl fix\n"+
				"repo-oss | SUSE-2026-2 | security | important | --- | needed | curl fix\n"+
				"repo-oss | SUSE-2026-3 | security | moderate | --- | not needed | already applied\n", 0)
		b.PutCmd("zypper", []string{"--non-interactive", "--no-color", "repos"}, "# | Alias | Name | Enabled\n1 | repo-oss | Update repository | Yes\n", 0)
		b.PutCmdNotFound("zypper", []string{"--non-interactive", "--no-color", "search", "--installed-only", grubPackageForArch()})
		b.PutCmdNotFound("SUSEConnect", []string{"--status"})
		b.PutCmdNotFound("uname", []string{"-r"})
	})
	info, err := collectZypper(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if info.SecurityUpdates != 2 {
		t.Fatalf("expected 2 needed security patches, got %d: %+v", info.SecurityUpdates, info)
	}
	if info.CriticalUpdates != 1 || info.ImportantUpdates != 1 {
		t.Errorf("Critical/Important = %d/%d, want 1/1", info.CriticalUpdates, info.ImportantUpdates)
	}
	if !info.HasSecurityRepo {
		t.Error("expected HasSecurityRepo=true (repo output mentions 'update')")
	}
}

// TestCollectZypper_MalformedLineAndNoSecurityRepo covers a pipe-table line
// with too few fields (must be skipped, not indexed out-of-range) and the
// "no security repo configured" status branch.
func TestCollectZypper_MalformedLineAndNoSecurityRepo(t *testing.T) {
	withFixtureSource(t, func(b *source.Bundle) {
		b.PutCmd("zypper", []string{"--non-interactive", "--no-color", "list-patches", "--category", "security"},
			"Repository | Name | Category | Severity | Interactive | Status | Summary\n"+
				"security only 3 fields\n"+ // < 6 pipe-fields after split, must be skipped
				"repo-oss | SUSE-2026-1 | security | critical | --- | needed | openssl fix\n", 0)
		b.PutCmd("zypper", []string{"--non-interactive", "--no-color", "repos"},
			"# | Alias | Name | Enabled\n1 | repo-oss | Main Repository | Yes\n", 0)
		b.PutCmdNotFound("zypper", []string{"--non-interactive", "--no-color", "search", "--installed-only", grubPackageForArch()})
		b.PutCmdNotFound("SUSEConnect", []string{"--status"})
		b.PutCmdNotFound("uname", []string{"-r"})
	})
	info, err := collectZypper(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if info.SecurityUpdates != 1 {
		t.Errorf("SecurityUpdates = %d, want 1 (malformed line excluded)", info.SecurityUpdates)
	}
	if info.HasSecurityRepo {
		t.Error("expected HasSecurityRepo=false (no repo name/alias indicates security/update)")
	}
	if info.Status != "no-security-repo" {
		t.Errorf("Status = %q, want no-security-repo", info.Status)
	}
}

func TestCollectZypper_LockedExhaustsRetries(t *testing.T) {
	withFixtureSource(t, func(b *source.Bundle) {
		b.PutCmd("zypper", []string{"--non-interactive", "--no-color", "list-patches", "--category", "security"},
			"", 7) // combined output empty, exit 7 (locked) every time — runCmdCombined folds stderr in, but
	})
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	info, err := collectZypper(ctx)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if info.Status != "query-failed" {
		t.Fatalf("Status = %q, want query-failed", info.Status)
	}
}

// TestCollectZypper_LockedCancelledDuringBackoff drives the actual retry-loop
// cancellation branch: the fixture output DOES match zypperLocked (unlike
// TestCollectZypper_LockedExhaustsRetries's empty output, which short-circuits
// on attempt 1 via the !locked break before ever reaching sleepCtx), and a
// short parent context expires mid-800ms backoff so sleepCtx returns false —
// "ctx cancelled — don't spin" — rather than exhausting all 5 attempts.
func TestCollectZypper_LockedCancelledDuringBackoff(t *testing.T) {
	withFixtureSource(t, func(b *source.Bundle) {
		b.PutCmd("zypper", []string{"--non-interactive", "--no-color", "list-patches", "--category", "security"},
			"System management is locked by the application with pid 123.\n", 7)
	})
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	info, err := collectZypper(ctx)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if info.Status != "query-failed" {
		t.Fatalf("Status = %q, want query-failed", info.Status)
	}
	if info.StatusReason != "zypper is locked by another process — security updates not verified" {
		t.Errorf("StatusReason = %q, want the locked reason", info.StatusReason)
	}
}

// ── zypperHasSecurityRepo ─────────────────────────────────────────────────────

func TestZypperHasSecurityRepo_KeywordMatch(t *testing.T) {
	withFixtureSource(t, func(b *source.Bundle) {
		b.PutCmd("zypper", []string{"--non-interactive", "--no-color", "repos"}, "openSUSE-Tumbleweed-Update\n", 0)
	})
	if !zypperHasSecurityRepo(context.Background()) {
		t.Error("expected true for a repo listing containing 'update'")
	}
}

func TestZypperHasSecurityRepo_SUSEConnectRegistered(t *testing.T) {
	withFixtureSource(t, func(b *source.Bundle) {
		b.PutCmd("zypper", []string{"--non-interactive", "--no-color", "repos"}, "repo-oss\n", 0)
		b.PutCmd("SUSEConnect", []string{"--status"}, `[{"identifier":"SLES","status":"Registered"}]`, 0)
	})
	if !zypperHasSecurityRepo(context.Background()) {
		t.Error("expected true when SUSEConnect reports registered")
	}
}

func TestZypperHasSecurityRepo_NoneFound(t *testing.T) {
	withFixtureSource(t, func(b *source.Bundle) {
		b.PutCmd("zypper", []string{"--non-interactive", "--no-color", "repos"}, "repo-oss\n", 0)
		b.PutCmdNotFound("SUSEConnect", []string{"--status"})
	})
	if zypperHasSecurityRepo(context.Background()) {
		t.Error("expected false with no security keyword and no SUSEConnect")
	}
}

func TestZypperHasSecurityRepo_QueryFails(t *testing.T) {
	withFixtureSource(t, func(b *source.Bundle) {
		b.PutCmdNotFound("zypper", []string{"--non-interactive", "--no-color", "repos"})
	})
	if zypperHasSecurityRepo(context.Background()) {
		t.Error("expected false when zypper repos itself fails")
	}
}

// ── checkSUSEMigrationRisks ───────────────────────────────────────────────────

func grubPackageForArch() string {
	if runtime.GOARCH == "arm64" {
		return "grub2-arm64-efi"
	}
	return "grub2-x86_64-efi"
}

func TestCheckSUSEMigrationRisks_GrubUnlocked(t *testing.T) {
	grubPkg := grubPackageForArch()
	withFixtureSource(t, func(b *source.Bundle) {
		b.PutCmd("zypper", []string{"--non-interactive", "--no-color", "search", "--installed-only", grubPkg},
			"i | "+grubPkg+" | package | x86_64 | repo-oss\n", 0)
		b.PutCmd("zypper", []string{"--non-interactive", "--no-color", "locks"}, "", 0)
		b.PutCmdNotFound("SUSEConnect", []string{"--status"})
		b.PutCmdNotFound("uname", []string{"-r"})
	})
	risks := checkSUSEMigrationRisks(context.Background())
	if len(risks) != 1 || !strings.Contains(risks[0], "NOT locked") {
		t.Fatalf("expected 1 grub-unlocked risk, got %+v", risks)
	}
}

func TestCheckSUSEMigrationRisks_GrubLockedNoRisk(t *testing.T) {
	grubPkg := grubPackageForArch()
	withFixtureSource(t, func(b *source.Bundle) {
		b.PutCmd("zypper", []string{"--non-interactive", "--no-color", "search", "--installed-only", grubPkg},
			"i | "+grubPkg+" | package | x86_64 | repo-oss\n", 0)
		b.PutCmd("zypper", []string{"--non-interactive", "--no-color", "locks"}, grubPkg+"\n", 0)
		b.PutCmdNotFound("SUSEConnect", []string{"--status"})
		b.PutCmdNotFound("uname", []string{"-r"})
	})
	risks := checkSUSEMigrationRisks(context.Background())
	if len(risks) != 0 {
		t.Errorf("expected no risks when grub package is locked, got %+v", risks)
	}
}

func TestCheckSUSEMigrationRisks_NotRegistered(t *testing.T) {
	grubPkg := grubPackageForArch()
	withFixtureSource(t, func(b *source.Bundle) {
		b.PutCmdNotFound("zypper", []string{"--non-interactive", "--no-color", "search", "--installed-only", grubPkg})
		b.PutCmd("SUSEConnect", []string{"--status"}, "This system is not registered\n", 0)
		b.PutCmdNotFound("uname", []string{"-r"})
	})
	risks := checkSUSEMigrationRisks(context.Background())
	found := false
	for _, r := range risks {
		if strings.Contains(r, "not registered") {
			found = true
		}
	}
	if !found {
		t.Errorf("expected a not-registered risk, got %+v", risks)
	}
}

func TestCheckSUSEMigrationRisks_PendingReboot(t *testing.T) {
	grubPkg := grubPackageForArch()
	withFixtureSource(t, func(b *source.Bundle) {
		b.PutCmdNotFound("zypper", []string{"--non-interactive", "--no-color", "search", "--installed-only", grubPkg})
		b.PutCmdNotFound("SUSEConnect", []string{"--status"})
		b.PutCmd("uname", []string{"-r"}, "5.14.21-150500.55.7-default\n", 0)
		b.PutCmd("ls", []string{"/boot"}, "vmlinuz-5.14.21-150500.55.30-default\nvmlinuz-5.14.21-150500.55.7-default\n", 0)
	})
	risks := checkSUSEMigrationRisks(context.Background())
	found := false
	for _, r := range risks {
		if strings.Contains(r, "reboot") {
			found = true
		}
	}
	if !found {
		t.Errorf("expected a pending-reboot risk, got %+v", risks)
	}
}

func TestCheckSUSEMigrationRisks_None(t *testing.T) {
	grubPkg := grubPackageForArch()
	withFixtureSource(t, func(b *source.Bundle) {
		b.PutCmdNotFound("zypper", []string{"--non-interactive", "--no-color", "search", "--installed-only", grubPkg})
		b.PutCmdNotFound("SUSEConnect", []string{"--status"})
		b.PutCmdNotFound("uname", []string{"-r"})
	})
	risks := checkSUSEMigrationRisks(context.Background())
	if len(risks) != 0 {
		t.Errorf("expected no risks, got %+v", risks)
	}
}

// ── collectPackageIntegrity dispatcher ────────────────────────────────────────

func TestCollectPackageIntegrity_DNF(t *testing.T) {
	withFixtureSource(t, func(b *source.Bundle) {
		b.PutCmdNotFound("dnf", []string{"check", "--quiet"})
		b.PutCmdNotFound("rpm", []string{"--verify", "bash", "coreutils", "systemd", "glibc", "openssl-libs"})
		b.PutCmd("ldconfig", []string{"-p"}, "libc.so.6 (libc6,x86-64) => /lib/x86_64-linux-gnu/libc.so.6\n", 0)
	})
	pi := collectPackageIntegrity(context.Background(), "dnf")
	if !pi.LdconfigOK {
		t.Error("expected LdconfigOK=true")
	}
}

func TestCollectPackageIntegrity_UnknownManagerStillRunsCrossDistroChecks(t *testing.T) {
	withFixtureSource(t, func(b *source.Bundle) {
		b.PutCmdNotFound("ldconfig", []string{"-p"})
	})
	pi := collectPackageIntegrity(context.Background(), "brew")
	if pi.LdconfigOK {
		t.Error("expected LdconfigOK=false when ldconfig fails")
	}
}

// ── pkgIntegrityDNF ───────────────────────────────────────────────────────────

func TestPkgIntegrityDNF_Clean(t *testing.T) {
	withFixtureSource(t, func(b *source.Bundle) {
		b.PutCmd("dnf", []string{"check", "--quiet"}, "", 0)
		b.PutCmd("rpm", []string{"--verify", "bash", "coreutils", "systemd", "glibc", "openssl-libs"}, "", 0)
	})
	pi := &models.PackageIntegrity{}
	pkgIntegrityDNF(context.Background(), pi)
	if len(pi.BrokenPackages) != 0 || len(pi.RPMVerifyFailed) != 0 || pi.VerifyTimedOut {
		t.Errorf("expected a clean result, got %+v", pi)
	}
}

func TestPkgIntegrityDNF_BrokenAndVerifyFailures(t *testing.T) {
	withFixtureSource(t, func(b *source.Bundle) {
		b.PutCmd("dnf", []string{"check", "--quiet"}, "package foo has unsatisfied dependency bar\n", 1)
		// rpm -V format: 8-char attribute string + space + 'c '(config)/blank + path.
		// Position 9 (0-indexed) is the config-file marker; keep it non-'c' so the
		// line is NOT skipped as an expected config-file modification.
		b.PutCmd("rpm", []string{"--verify", "bash", "coreutils", "systemd", "glibc", "openssl-libs"},
			"S.5....T.  /bin/bash\n", 1)
	})
	pi := &models.PackageIntegrity{}
	pkgIntegrityDNF(context.Background(), pi)
	if len(pi.BrokenPackages) != 1 {
		t.Errorf("BrokenPackages = %+v, want 1 entry", pi.BrokenPackages)
	}
	if len(pi.RPMVerifyFailed) != 1 {
		t.Errorf("RPMVerifyFailed = %+v, want 1 entry", pi.RPMVerifyFailed)
	}
}

func TestPkgIntegrityDNF_VerifyTimedOut(t *testing.T) {
	withFixtureSource(t, func(b *source.Bundle) {
		b.PutCmd("dnf", []string{"check", "--quiet"}, "", 0)
	})
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // pre-cancel so rpmCtx.Err() != nil inside pkgIntegrityDNF
	pi := &models.PackageIntegrity{}
	pkgIntegrityDNF(ctx, pi)
	if !pi.VerifyTimedOut {
		t.Error("expected VerifyTimedOut=true for a pre-cancelled context")
	}
}

// ── pkgIntegrityLdconfig / pkgIntegrityLdd ───────────────────────────────────

func TestPkgIntegrityLdconfig_OK(t *testing.T) {
	withFixtureSource(t, func(b *source.Bundle) {
		b.PutCmd("ldconfig", []string{"-p"}, "1234 libs found in cache\n", 0)
	})
	pi := &models.PackageIntegrity{}
	pkgIntegrityLdconfig(context.Background(), pi)
	if !pi.LdconfigOK {
		t.Error("expected LdconfigOK=true")
	}
}

func TestPkgIntegrityLdconfig_Fails(t *testing.T) {
	withFixtureSource(t, func(b *source.Bundle) {
		b.PutCmdNotFound("ldconfig", []string{"-p"})
	})
	pi := &models.PackageIntegrity{}
	pkgIntegrityLdconfig(context.Background(), pi)
	if pi.LdconfigOK {
		t.Error("expected LdconfigOK=false")
	}
}

func TestPkgIntegrityLdd_MissingLibDetected(t *testing.T) {
	withFixtureSource(t, func(b *source.Bundle) {
		b.PutStat("/bin/ls", source.FileMeta{})
		b.PutCmd("ldd", []string{"/bin/ls"},
			"linux-vdso.so.1 (0x00007fff)\nlibfoo.so.2 => not found\nlibc.so.6 => /lib/x86_64-linux-gnu/libc.so.6\n", 0)
		// /usr/bin/ssh and /usr/bin/python3 are left unseeded — statFile replays
		// ErrNotRecorded, which fileExists treats as "doesn't exist" (not permission).
	})
	pi := &models.PackageIntegrity{}
	pkgIntegrityLdd(context.Background(), pi)
	if len(pi.MissingLibs) != 1 || !strings.Contains(pi.MissingLibs[0], "libfoo.so.2") {
		t.Fatalf("MissingLibs = %+v, want 1 entry referencing libfoo.so.2", pi.MissingLibs)
	}
	if !strings.Contains(pi.MissingLibs[0], "ls") {
		t.Errorf("expected the canary binary name in the message, got %q", pi.MissingLibs[0])
	}
}

func TestPkgIntegrityLdd_BinaryAbsent(t *testing.T) {
	withFixtureSource(t, func(b *source.Bundle) {
		// All three canary paths left unseeded — statFile replays ErrNotRecorded,
		// which fileExists treats as "doesn't exist".
	})
	pi := &models.PackageIntegrity{}
	pkgIntegrityLdd(context.Background(), pi)
	if len(pi.MissingLibs) != 0 {
		t.Errorf("expected no findings when no canary binaries exist, got %+v", pi.MissingLibs)
	}
}

func TestPkgIntegrityLdd_LddFails(t *testing.T) {
	withFixtureSource(t, func(b *source.Bundle) {
		b.PutStat("/bin/ls", source.FileMeta{})
		b.PutCmdNotFound("ldd", []string{"/bin/ls"})
		// /usr/bin/ssh and /usr/bin/python3 left unseeded — treated as absent.
	})
	pi := &models.PackageIntegrity{}
	pkgIntegrityLdd(context.Background(), pi)
	if len(pi.MissingLibs) != 0 {
		t.Errorf("expected no findings when ldd itself fails, got %+v", pi.MissingLibs)
	}
}
