package analysis

import (
	"strings"
	"testing"

	"github.com/keyorixhq/dashdiag/internal/models"
)

// Round-6 characterization tests for the long-tail heuristics: package updates &
// integrity, firmware, cloud-metadata events, auditd, huge pages, CPU frequency
// governor, D-Bus, launchd, and cgroup-v2 slices. Pure functions; reuses assertLevel.

func TestCheckPackages(t *testing.T) {
	tests := []struct {
		name string
		pkg  models.PackagesInfo
		want string
	}{
		{"no security repo is WARN", models.PackagesInfo{Status: "no-security-repo"}, "WARN"},
		{"no updates is clean", models.PackagesInfo{SecurityUpdates: 0}, ""},
		{"stale metadata is INFO (unverified, not up-to-date)", models.PackagesInfo{SecurityUpdates: 0, Status: "stale-metadata", PackageManager: "apt", StatusReason: "update metadata is 40 days old — cannot confirm packages are up to date"}, "INFO"},
		// The security query itself failed → INFO "couldn't verify", never a silent
		// clean 0-updates OK (dnf/zypper/apt errored; zypper used to claim Status:OK).
		{"query failed is INFO (unverified, not clean)", models.PackagesInfo{SecurityUpdates: 0, Status: "query-failed", PackageManager: "dnf", StatusReason: "dnf advisory/updateinfo unavailable"}, "INFO"},
		{"ESM-only updates is WARN", models.PackagesInfo{SecurityUpdates: 0, ESMUpdates: 3}, "WARN"},
		// dnf/zypper expose a REAL per-advisory severity, so a Critical update is a CRIT.
		{"critical updates is CRIT (dnf real severity)", models.PackagesInfo{SecurityUpdates: 5, CriticalUpdates: 1, PackageManager: "dnf"}, "CRIT"},
		// apt has NO CVSS — "Critical" is inferred from the package name, so it must
		// NOT mint a hard CRIT (would CRIT a host just because openssl has an update).
		{"apt critical is WARN not CRIT (name-inferred, no CVSS)", models.PackagesInfo{SecurityUpdates: 5, CriticalUpdates: 3, PackageManager: "apt"}, "WARN"},
		{"important updates is WARN", models.PackagesInfo{SecurityUpdates: 5, ImportantUpdates: 1, PackageManager: "apt"}, "WARN"},
		// Regression guard: Homebrew has no security metadata — `brew outdated`
		// lists every outdated formula, not vulnerability-relevant ones. A dev
		// Mac with routine outdated formulae must NOT get a security WARN.
		{"brew outdated formulae is INFO not a security WARN", models.PackagesInfo{SecurityUpdates: 3, PackageManager: "brew"}, "INFO"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assertLevel(t, checkPackages(tt.pkg), tt.want)
		})
	}
}

// TestNoSecurityRepoHints is a regression guard: dnf/zypper hosts with no
// enabled security repo previously fell through this exact WARN with hard-coded
// apt/Debian/Ubuntu fix hints (both collectors set only StatusReason, never
// Status, so they never even reached this branch — a separate false-OK also
// fixed). Confirms the hint text now matches the actual package manager.
func TestNoSecurityRepoHints(t *testing.T) {
	dnf := strings.Join(noSecurityRepoHints("dnf"), " ")
	if !strings.Contains(dnf, "dnf") {
		t.Errorf("dnf hints should mention dnf, not apt/Debian/Ubuntu: %q", dnf)
	}
	zypper := strings.Join(noSecurityRepoHints("zypper"), " ")
	if !strings.Contains(zypper, "zypper") {
		t.Errorf("zypper hints should mention zypper, not apt/Debian/Ubuntu: %q", zypper)
	}
	apt := strings.Join(noSecurityRepoHints("apt"), " ")
	if !strings.Contains(apt, "Debian") {
		t.Errorf("apt/default hints should keep the Debian/Ubuntu wording: %q", apt)
	}

	// Both dnf and zypper now actually reach this WARN (Status is set by the
	// collectors, not just StatusReason).
	for _, pm := range []string{"dnf", "zypper"} {
		got := checkPackages(models.PackagesInfo{Status: "no-security-repo", PackageManager: pm})
		assertLevel(t, got, "WARN")
	}
}

func TestCheckPackageIntegrity(t *testing.T) {
	tests := []struct {
		name string
		pi   models.PackageIntegrity
		want string
	}{
		{"healthy is clean", models.PackageIntegrity{LdconfigOK: true}, ""},
		{"broken packages is CRIT", models.PackageIntegrity{LdconfigOK: true, BrokenPackages: []string{"x"}}, "CRIT"},
		{"unmet deps is CRIT", models.PackageIntegrity{LdconfigOK: true, UnmetDeps: []string{"y"}}, "CRIT"},
		{"missing libs is CRIT", models.PackageIntegrity{LdconfigOK: true, MissingLibs: []string{"libz.so"}}, "CRIT"},
		{"rpm verify failures is WARN", models.PackageIntegrity{LdconfigOK: true, RPMVerifyFailed: []string{"/bin/ls"}}, "WARN"},
		{"ldconfig couldn't run is INFO not WARN", models.PackageIntegrity{LdconfigOK: false}, "INFO"},
		// A lock-blocked verify must report "couldn't verify" (INFO), never a silent clean.
		{"verify locked is INFO not silent-clean", models.PackageIntegrity{LdconfigOK: true, VerifyLocked: true}, "INFO"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assertLevel(t, checkPackageIntegrity(tt.pi), tt.want)
		})
	}
}

func TestCheckFirmware(t *testing.T) {
	assertLevel(t, checkFirmware(models.FirmwareInfo{Available: false}), "")
	assertLevel(t, checkFirmware(models.FirmwareInfo{Available: true, UpgradeCount: 0}), "")
	assertLevel(t, checkFirmware(models.FirmwareInfo{
		Available: true, UpgradeCount: 1, SecurityCount: 1,
		Upgrades: []models.FirmwareUpgrade{{Name: "BIOS", SecurityFix: true}},
	}), "WARN")
	assertLevel(t, checkFirmware(models.FirmwareInfo{Available: true, UpgradeCount: 1, SecurityCount: 0}), "INFO")
}

func TestCheckCloudMeta(t *testing.T) {
	assertLevel(t, checkCloudMeta(models.CloudInfo{Available: false}), "")
	assertLevel(t, checkCloudMeta(models.CloudInfo{Available: true, Provider: "aws", SpotTermination: true}), "CRIT")
	assertLevel(t, checkCloudMeta(models.CloudInfo{Available: true, Provider: "gcp", MaintenanceEvent: true}), "WARN")
}

func TestCheckAuditd(t *testing.T) {
	assertLevel(t, checkAuditd(models.AuditInfo{Available: false}), "")
	assertLevel(t, checkAuditd(models.AuditInfo{Available: true, Running: true}), "")
	assertLevel(t, checkAuditd(models.AuditInfo{Available: true, Running: false}), "WARN")
	assertLevel(t, checkAuditd(models.AuditInfo{Available: true, Running: true, AuditLogSizeGB: 15}), "WARN")

	// Regression guard: /var/log/audit/ is 0700 root:root, so a non-root run
	// can't distinguish "log is small" from "couldn't read it" without this
	// sentinel — a host with a runaway multi-GB audit log would otherwise read
	// healthy unprivileged (AuditLogSizeGB stays its zero value) while root
	// would WARN on the exact same log.
	unreadable := checkAuditd(models.AuditInfo{Available: true, Running: true, AuditLogSizeUnreadable: true})
	if !insightWithMsg(unreadable, "INFO", "not verified") {
		t.Errorf("unreadable audit log size should INFO 'not verified', got %+v", unreadable)
	}
	for _, ins := range unreadable {
		if ins.Level == "WARN" || ins.Level == "CRIT" {
			t.Errorf("unreadable audit log size must not alarm, got %s: %s", ins.Level, ins.Message)
		}
	}
}

func TestCheckHugePages(t *testing.T) {
	tests := []struct {
		name string
		h    models.HugePagesInfo
		want string
	}{
		{"not configured is silent", models.HugePagesInfo{Configured: 0, THPEnabled: false}, ""},
		{"mostly-unused static pages is WARN", models.HugePagesInfo{Configured: 100, Used: 10, ReservedGB: 2}, "WARN"},
		{"fully-used pages is INFO", models.HugePagesInfo{Configured: 100, Used: 100, ReservedGB: 1}, "INFO"},
		{"THP always is INFO", models.HugePagesInfo{THPEnabled: true, THPMode: "always"}, "INFO"},
		{"normal usage is clean", models.HugePagesInfo{Configured: 100, Used: 50, THPMode: "never"}, ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assertLevel(t, checkHugePages(tt.h), tt.want)
		})
	}
}

func TestCheckCPUFreq(t *testing.T) {
	loaded := defaultThresh
	loaded.CPULoadPct = 60 // CPU under load — a freq stuck below max is real throttling
	idle := defaultThresh
	idle.CPULoadPct = 3 // idle — min freq is normal, not throttling

	assertLevel(t, checkCPUFreq(models.CPUFreqInfo{Governor: ""}, defaultThresh), "") // unavailable
	assertLevel(t, checkCPUFreq(models.CPUFreqInfo{Governor: "performance"}, defaultThresh), "")
	// powersave on a legacy-driver server (acpi-cpufreq, no battery) → WARN (capped at min freq).
	assertLevel(t, checkCPUFreq(models.CPUFreqInfo{Governor: "powersave", CurrentMHz: 800, MaxMHz: 3000, ScalingDriver: "acpi-cpufreq"}, defaultThresh), "WARN")
	// Throttle WARN only fires under load...
	assertLevel(t, checkCPUFreq(models.CPUFreqInfo{Governor: "schedutil", ThrottledPct: 50, CurrentMHz: 1500, MaxMHz: 3000}, loaded), "WARN")
	// ...not on an IDLE box parked at min freq (the false-WARN fix), nor when load is unknown.
	assertLevel(t, checkCPUFreq(models.CPUFreqInfo{Governor: "schedutil", ThrottledPct: 80, CurrentMHz: 600, MaxMHz: 3000}, idle), "")
	assertLevel(t, checkCPUFreq(models.CPUFreqInfo{Governor: "schedutil", ThrottledPct: 80, CurrentMHz: 600, MaxMHz: 3000}, defaultThresh), "")

	// powersave on a BATTERY device (laptop / Steam Deck) → INFO, never WARN.
	// Found on the AMD-laptop capture (legacy/empty driver + battery).
	bat := checkCPUFreq(models.CPUFreqInfo{Governor: "powersave", CurrentMHz: 2096, MaxMHz: 4280, HasBattery: true}, defaultThresh)
	if hasLevel(bat, "WARN") {
		t.Errorf("powersave on battery must NOT WARN, got %+v", bat)
	}
	if !hasLevel(bat, "INFO") {
		t.Errorf("powersave on battery should INFO, got %+v", bat)
	}

	// powersave on intel_pstate / amd-pstate (active mode) → DYNAMIC, the modern
	// default → no finding at all (not WARN, not INFO). This is the false-WARN that
	// would otherwise fire on nearly every modern Intel/AMD bare-metal server.
	for _, drv := range []string{"intel_pstate", "amd-pstate-epp", "amd-pstate"} {
		got := checkCPUFreq(models.CPUFreqInfo{Governor: "powersave", CurrentMHz: 1200, MaxMHz: 3600, ScalingDriver: drv}, defaultThresh)
		if hasLevel(got, "WARN") || hasLevel(got, "INFO") {
			t.Errorf("powersave on %s (dynamic) must be silent, got %+v", drv, got)
		}
	}
}

func TestCheckDBus(t *testing.T) {
	assertLevel(t, checkDBus(models.DBusInfo{Status: "n/a"}), "") // not applicable
	assertLevel(t, checkDBus(models.DBusInfo{Active: true, Status: "active"}), "")
	assertLevel(t, checkDBus(models.DBusInfo{Active: false, Status: "failed"}), "CRIT")
	// TRIAGE §M — "unknown" means systemctl couldn't determine the state (alias
	// lookup miss / timeout), NOT that the bus is down. Must be INFO, never CRIT:
	// a live system with an active bus was false-CRITing because is-active
	// dbus.service returned empty→"unknown"→active:false→CRIT.
	assertLevel(t, checkDBus(models.DBusInfo{Active: false, Status: "unknown"}), "INFO")
	// "inactive" is a genuine down state and still CRITs.
	assertLevel(t, checkDBus(models.DBusInfo{Active: false, Status: "inactive"}), "CRIT")
	// Any other non-failed/non-inactive status (e.g. transient "activating") is
	// treated as undetermined, not a failure.
	assertLevel(t, checkDBus(models.DBusInfo{Active: false, Status: "activating"}), "INFO")
	// A failed bus with a captured LastError prepends it as the first hint.
	failedWithErr := checkDBus(models.DBusInfo{Active: false, Status: "failed", LastError: "Failed to activate service 'org.freedesktop.DBus'"})
	if !hasInsightMsg(failedWithErr, "CRIT", "D-Bus system message bus has failed") {
		t.Fatalf("expected the CRIT insight, got %+v", failedWithErr)
	}
	foundLastError := false
	for _, ins := range failedWithErr {
		for _, h := range ins.Hints {
			if strings.Contains(h, "last error: Failed to activate service") {
				foundLastError = true
			}
		}
	}
	if !foundLastError {
		t.Errorf("expected a 'last error:' hint from LastError, got %+v", failedWithErr)
	}
}

func TestCheckLaunchd(t *testing.T) {
	assertLevel(t, checkLaunchd(models.LaunchdInfo{}), "")
	assertLevel(t, checkLaunchd(models.LaunchdInfo{Failed: []models.LaunchdService{{Label: "com.example.daemon"}}}), "WARN")

	// More than 3 failed services truncates the inline list and appends a "+N more" suffix.
	many := checkLaunchd(models.LaunchdInfo{Failed: []models.LaunchdService{
		{Label: "com.example.one"}, {Label: "com.example.two"},
		{Label: "com.example.three"}, {Label: "com.example.four"}, {Label: "com.example.five"},
	}})
	if !hasInsightMsg(many, "WARN", "(+2 more)") {
		t.Errorf("expected a '+2 more' suffix when more than 3 services failed, got %+v", many)
	}
}

func TestCheckCgroupV2(t *testing.T) {
	slice := func(s models.CgroupSlice) models.CgroupV2Info {
		return models.CgroupV2Info{Available: true, Slices: []models.CgroupSlice{s}}
	}
	tests := []struct {
		name string
		cg   models.CgroupV2Info
		want string
	}{
		{"unavailable is silent", models.CgroupV2Info{Available: false}, ""},
		{"available and quiet is clean", models.CgroupV2Info{Available: true}, ""},
		// Cumulative since-boot counter — INFO context, not a live CRIT (recency is
		// owned by the windowed Logs/OOM check).
		{"cgroup oom counter is INFO", models.CgroupV2Info{Available: true, OOMKills: 1}, "INFO"},
		{"heavy CPU throttle is CRIT", slice(models.CgroupSlice{Name: "system.slice", ThrottledPct: 25}), "CRIT"},
		{"mild CPU throttle is WARN", slice(models.CgroupSlice{Name: "system.slice", ThrottledPct: 10}), "WARN"},
		{"memory near limit is CRIT", slice(models.CgroupSlice{Name: "user.slice", HasMemLimit: true, MemUsedPct: 95}), "CRIT"},
		{"memory elevated is WARN", slice(models.CgroupSlice{Name: "user.slice", HasMemLimit: true, MemUsedPct: 80}), "WARN"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assertLevel(t, checkCgroupV2(tt.cg), tt.want)
		})
	}
}

// TestCheckCgroupV2_Units is a boundary table for the per-unit (systemd
// service / container) drill-down added alongside the top-level slice
// checks above — same 5%/20% throttle and 75%/90% memory thresholds, at/
// below/above each mark.
func TestCheckCgroupV2_Units(t *testing.T) {
	t.Parallel()
	unit := func(u models.CgroupUnit) models.CgroupV2Info {
		return models.CgroupV2Info{Available: true, Units: []models.CgroupUnit{u}}
	}
	tests := []struct {
		name string
		cg   models.CgroupV2Info
		want string
	}{
		{"throttle at 5% is clean (boundary)", unit(models.CgroupUnit{Name: "postgresql.service", ThrottledPct: 5}), ""},
		{"throttle just above 5% is WARN", unit(models.CgroupUnit{Name: "postgresql.service", ThrottledPct: 5.1}), "WARN"},
		{"throttle at 20% is WARN (boundary)", unit(models.CgroupUnit{Name: "postgresql.service", ThrottledPct: 20}), "WARN"},
		{"throttle just above 20% is CRIT", unit(models.CgroupUnit{Name: "postgresql.service", ThrottledPct: 20.1}), "CRIT"},
		{"container throttle also fires", unit(models.CgroupUnit{Name: "container:abc123def456", IsContainer: true, ThrottledPct: 25}), "CRIT"},
		{"mem at 75% is clean (boundary)", unit(models.CgroupUnit{Name: "postgresql.service", HasMemLimit: true, MemUsedPct: 75}), ""},
		{"mem just above 75% is WARN", unit(models.CgroupUnit{Name: "postgresql.service", HasMemLimit: true, MemUsedPct: 75.1}), "WARN"},
		{"mem at 90% is WARN (boundary)", unit(models.CgroupUnit{Name: "postgresql.service", HasMemLimit: true, MemUsedPct: 90}), "WARN"},
		{"mem just above 90% is CRIT", unit(models.CgroupUnit{Name: "postgresql.service", HasMemLimit: true, MemUsedPct: 90.1}), "CRIT"},
		{"mem without a limit never fires", unit(models.CgroupUnit{Name: "postgresql.service", HasMemLimit: false, MemUsedPct: 99}), ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			assertLevel(t, checkCgroupV2(tt.cg), tt.want)
		})
	}
}
