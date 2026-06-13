package analysis

import (
	"fmt"
	"runtime"
	"strings"
	"testing"

	"github.com/keyorixhq/dashdiag/internal/models"
	"github.com/keyorixhq/dashdiag/internal/platform"
	"github.com/keyorixhq/dashdiag/internal/runner"
)

var defaultThresh = DefaultThresholds(platform.EnvBareMetal)

func res(data interface{}) []runner.Result {
	return []runner.Result{{Name: "test", Data: data}}
}

func hasLevel(insights []models.Insight, level string) bool {
	for _, ins := range insights {
		if ins.Level == level {
			return true
		}
	}
	return false
}

func assertLevel(t *testing.T, insights []models.Insight, wantLevel string) {
	t.Helper()
	if wantLevel == "" {
		if len(insights) != 0 {
			t.Errorf("expected no insights, got %d: %+v", len(insights), insights)
		}
		return
	}
	if !hasLevel(insights, wantLevel) {
		t.Errorf("expected insight level %q, got: %+v", wantLevel, insights)
	}
}

// ── CPU ──────────────────────────────────────────────────────────────────────

func TestCPUThresholds(t *testing.T) {
	cases := []struct {
		name      string
		loadPct   float64
		wantLevel string
	}{
		{"below warn", 69.9, ""},
		{"at warn", 70.0, "WARN"},
		{"above warn", 75.0, "WARN"},
		{"at crit", 90.0, "CRIT"},
		{"above crit", 95.0, "CRIT"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			insights := ApplyThresholds(res(models.CPUInfo{LoadPct: tc.loadPct, NumCPU: 4}), defaultThresh, platform.EnvBareMetal, platform.ContainerContext{})
			assertLevel(t, insights, tc.wantLevel)
		})
	}
}

// ── Memory ───────────────────────────────────────────────────────────────────

func TestMemoryUsedPctThresholds(t *testing.T) {
	cases := []struct {
		name string
		pct  float64
		want string
	}{
		{"below warn", 79.9, ""},
		{"at warn", 80.0, "WARN"},
		{"above warn", 85.0, "WARN"},
		{"at crit", 95.0, "CRIT"},
		{"above crit", 97.0, "CRIT"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			insights := ApplyThresholds(res(models.MemoryInfo{UsedPct: tc.pct, TotalGB: 16}), defaultThresh, platform.EnvBareMetal, platform.ContainerContext{})
			assertLevel(t, insights, tc.want)
		})
	}
}

func TestMemoryOverCommitted(t *testing.T) {
	// CommitLimit is only enforced under strict accounting (vm.overcommit_memory=2),
	// so only mode 2 is a real OOM risk worth a CRIT.
	strict := ApplyThresholds(res(models.MemoryInfo{OverCommitted: true, OvercommitMode: 2, TotalGB: 16}), defaultThresh, platform.EnvBareMetal, platform.ContainerContext{})
	if !hasLevel(strict, "CRIT") {
		t.Error("expected CRIT for OverCommitted=true in strict mode (2)")
	}
	// Default heuristic mode (0): exceeding CommitLimit is normal — no false CRIT.
	heuristic := ApplyThresholds(res(models.MemoryInfo{OverCommitted: true, OvercommitMode: 0, TotalGB: 16}), defaultThresh, platform.EnvBareMetal, platform.ContainerContext{})
	if hasLevel(heuristic, "CRIT") {
		t.Error("must NOT CRIT for OverCommitted=true in heuristic mode (0)")
	}
}

func TestMemorySlabThresholds(t *testing.T) {
	// TotalGB=16 → threshold 20% = 3.2 GB = 3276.8 MB
	cases := []struct {
		name   string
		slabMB float64
		want   string
	}{
		{"below warn", 3200, ""},
		{"at warn", 3277, "WARN"},
		{"above warn", 4000, "WARN"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			m := models.MemoryInfo{TotalGB: 16, SlabMB: tc.slabMB}
			insights := ApplyThresholds(res(m), defaultThresh, platform.EnvBareMetal, platform.ContainerContext{})
			found := hasLevel(insights, "WARN")
			wantFound := tc.want == "WARN"
			if found != wantFound {
				t.Errorf("SlabMB=%.0f: gotWARN=%v, wantWARN=%v", tc.slabMB, found, wantFound)
			}
		})
	}
}

// ── Disk ─────────────────────────────────────────────────────────────────────

func TestDiskUsedPctThresholds(t *testing.T) {
	cases := []struct {
		name string
		pct  float64
		want string
	}{
		{"below warn", 79.9, ""},
		{"at warn", 80.0, "WARN"},
		{"above warn", 85.0, "WARN"},
		{"at crit", 90.0, "CRIT"},
		{"above crit", 95.0, "CRIT"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			d := models.DiskInfo{Filesystems: []models.FilesystemInfo{{Mount: "/", UsedPct: tc.pct}}}
			insights := ApplyThresholds(res(d), defaultThresh, platform.EnvBareMetal, platform.ContainerContext{})
			assertLevel(t, insights, tc.want)
		})
	}
}

func TestDiskInodesUsedPctThresholds(t *testing.T) {
	cases := []struct {
		name string
		pct  float64
		want string
	}{
		{"below warn", 79.9, ""},
		{"at warn", 80.0, "WARN"},
		{"at crit", 90.0, "CRIT"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			d := models.DiskInfo{Filesystems: []models.FilesystemInfo{{Mount: "/var", InodesUsedPct: tc.pct}}}
			insights := ApplyThresholds(res(d), defaultThresh, platform.EnvBareMetal, platform.ContainerContext{})
			assertLevel(t, insights, tc.want)
		})
	}
}

// ── Swap ─────────────────────────────────────────────────────────────────────

func TestSwapUsedPctThresholds(t *testing.T) {
	cases := []struct {
		name string
		pct  float64
		want string
	}{
		{"below warn", 19.9, ""},
		{"at warn", 20.0, "WARN"},
		{"above warn", 40.0, "WARN"},
		{"at crit", 60.0, "CRIT"},
		{"above crit", 75.0, "CRIT"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			insights := ApplyThresholds(res(models.SwapInfo{UsedPct: tc.pct}), defaultThresh, platform.EnvBareMetal, platform.ContainerContext{})
			assertLevel(t, insights, tc.want)
		})
	}
}

func TestSwapActivityThresholds(t *testing.T) {
	cases := []struct {
		name      string
		pagesIn   float64
		pagesOut  float64
		zramDevs  int
		wantLevel string
	}{
		{"no activity", 0, 0, 0, ""},
		{"trivial churn below floor is silent", 1, 0, 0, ""}, // was a false WARN at >0
		{"trivial churn below floor (out)", 0, 40, 0, ""},    // still under the 50 floor
		{"moderate disk swap is WARN", 60, 0, 0, "WARN"},
		{"moderate disk swap (out) is WARN", 0, 60, 0, "WARN"},
		{"crit swap in", 101, 0, 0, "CRIT"},
		{"crit swap out", 0, 101, 0, "CRIT"},
		// zram-backed: moderate paging is compressed-RAM churn, not disk thrash.
		{"moderate zram swap is INFO not WARN", 60, 0, 1, "INFO"},
		{"trivial zram churn still below floor", 1, 0, 1, ""},
		{"heavy zram swap still CRIT", 101, 0, 1, "CRIT"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s := models.SwapInfo{PagesInPerSec: tc.pagesIn, PagesOutPerSec: tc.pagesOut, ZramDevices: tc.zramDevs}
			insights := ApplyThresholds(res(s), defaultThresh, platform.EnvBareMetal, platform.ContainerContext{})
			assertLevel(t, insights, tc.wantLevel)
		})
	}
}

func TestSwapMacOSPressureGating(t *testing.T) {
	// macOS: high swap alone (pressure == 1 = normal) must never trigger an alert.
	noAlert := []struct {
		name string
		pct  float64
	}{
		{"50pct normal pressure", 50},
		{"74pct normal pressure", 74},
		{"80pct normal pressure", 80},
		{"95pct normal pressure", 95},
	}
	for _, tc := range noAlert {
		t.Run(tc.name, func(t *testing.T) {
			s := models.SwapInfo{UsedPct: tc.pct, PagesInPerSec: -1, PagesOutPerSec: -1, MemPressureLevel: 1}
			insights := ApplyThresholds(res(s), defaultThresh, platform.EnvBareMetal, platform.ContainerContext{})
			if len(insights) != 0 {
				t.Errorf("expected no insights at %.0f%% with normal pressure, got %+v", tc.pct, insights)
			}
		})
	}

	// macOS: high swap WITH elevated pressure triggers.
	withPressure := []struct {
		name     string
		pct      float64
		pressure int
		want     string
	}{
		{"74pct warn pressure — below threshold", 74, 2, ""},
		{"75pct warn pressure — at threshold", 75, 2, "WARN"},
		{"80pct warn pressure", 80, 2, "WARN"},
		{"89pct warn pressure — below crit", 89, 2, "WARN"},
		{"90pct crit pressure", 90, 2, "CRIT"},
		{"95pct urgent pressure", 95, 3, "CRIT"},
	}
	for _, tc := range withPressure {
		t.Run(tc.name, func(t *testing.T) {
			s := models.SwapInfo{UsedPct: tc.pct, PagesInPerSec: -1, PagesOutPerSec: -1, MemPressureLevel: tc.pressure}
			insights := ApplyThresholds(res(s), defaultThresh, platform.EnvBareMetal, platform.ContainerContext{})
			assertLevel(t, insights, tc.want)
		})
	}
}

// ── IO ───────────────────────────────────────────────────────────────────────

func TestIOUtilPctThresholds(t *testing.T) {
	cases := []struct {
		name string
		pct  float64
		want string
	}{
		{"below warn", 59.9, ""},
		{"at warn", 60.0, "WARN"},
		{"above warn", 70.0, "WARN"},
		{"at crit", 85.0, "CRIT"},
		{"above crit", 90.0, "CRIT"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			io := models.IOInfo{Devices: []models.IODeviceInfo{{Name: "sda", UtilPct: tc.pct}}}
			insights := ApplyThresholds(res(io), defaultThresh, platform.EnvBareMetal, platform.ContainerContext{})
			assertLevel(t, insights, tc.want)
		})
	}
}

func TestIOAwaitMsThresholds_BareMetal(t *testing.T) {
	// EnvBareMetal: warn=1ms, crit=5ms
	thresh := DefaultThresholds(platform.EnvBareMetal)
	cases := []struct {
		name string
		ms   float64
		want string
	}{
		{"below warn", 0.9, ""},
		{"at warn", 1.0, "WARN"},
		{"above warn", 3.0, "WARN"},
		{"at crit", 5.0, "CRIT"},
		{"above crit", 8.0, "CRIT"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			io := models.IOInfo{Devices: []models.IODeviceInfo{{Name: "sda", AwaitMs: tc.ms}}}
			insights := ApplyThresholds(res(io), thresh, platform.EnvBareMetal, platform.ContainerContext{})
			assertLevel(t, insights, tc.want)
		})
	}
}

func TestIOAwaitMsThresholds_EBS(t *testing.T) {
	// EnvAWSEBS: warn=5ms, crit=20ms
	thresh := DefaultThresholds(platform.EnvAWSEBS)
	cases := []struct {
		name string
		ms   float64
		want string
	}{
		{"below warn", 4.9, ""},
		{"at warn", 5.0, "WARN"},
		{"at crit", 20.0, "CRIT"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			io := models.IOInfo{Devices: []models.IODeviceInfo{{Name: "xvda", AwaitMs: tc.ms}}}
			insights := ApplyThresholds(res(io), thresh, platform.EnvAWSEBS, platform.ContainerContext{})
			assertLevel(t, insights, tc.want)
		})
	}
}

// ── Network ──────────────────────────────────────────────────────────────────

func TestNetworkGatewayPingThresholds(t *testing.T) {
	cases := []struct {
		name string
		ms   float64
		want string
	}{
		{"ok", 10, ""},
		{"warn", 100, "WARN"},
		{"crit", 300, "CRIT"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			insights := ApplyThresholds(res(models.NetworkInfo{GatewayPingMs: tc.ms}), defaultThresh, platform.EnvBareMetal, platform.ContainerContext{})
			assertLevel(t, insights, tc.want)
		})
	}
}

func TestNetworkDNSThresholds(t *testing.T) {
	cases := []struct {
		name string
		ms   float64
		want string
	}{
		// Thresholds shared with dsd net (analysis.DNSResolveLevel): WARN 100, CRIT 500.
		{"ok", 50, ""},
		{"warn", 200, "WARN"},
		{"crit", 500, "CRIT"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			insights := ApplyThresholds(res(models.NetworkInfo{DNSResolvesMs: tc.ms}), defaultThresh, platform.EnvBareMetal, platform.ContainerContext{})
			assertLevel(t, insights, tc.want)
		})
	}
}

func TestNetworkCloseWaitThresholds(t *testing.T) {
	cases := []struct {
		name  string
		count int
		want  string
	}{
		{"ok", 50, ""},
		{"warn", 200, "WARN"},
		{"crit", 600, "CRIT"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			insights := ApplyThresholds(res(models.NetworkInfo{CloseWaitCount: tc.count}), defaultThresh, platform.EnvBareMetal, platform.ContainerContext{})
			assertLevel(t, insights, tc.want)
		})
	}
}

// ── Clock ────────────────────────────────────────────────────────────────────

func TestClockNilPointer(t *testing.T) {
	results := []runner.Result{{Name: "Clock", Data: (*models.ClockInfo)(nil)}}
	insights := ApplyThresholds(results, defaultThresh, platform.EnvBareMetal, platform.ContainerContext{})
	if len(insights) != 0 {
		t.Errorf("expected no insights for nil *ClockInfo, got %+v", insights)
	}
}

func TestClockNotSynced(t *testing.T) {
	insights := ApplyThresholds(res(models.ClockInfo{Synced: false, OffsetMs: -1}), defaultThresh, platform.EnvBareMetal, platform.ContainerContext{})
	if !hasLevel(insights, "CRIT") {
		t.Error("expected CRIT for unsynced clock")
	}
}

func TestClockOffsetThresholds(t *testing.T) {
	cases := []struct {
		name     string
		offsetMs float64
		want     string
	}{
		{"ok", 50, ""},
		{"warn positive", 150, "WARN"},
		{"warn negative", -150, "WARN"},
		{"crit positive", 600, "CRIT"},
		{"crit negative", -600, "CRIT"},
		{"unavailable sentinel", -1, ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			insights := ApplyThresholds(res(models.ClockInfo{Synced: true, OffsetMs: tc.offsetMs}), defaultThresh, platform.EnvBareMetal, platform.ContainerContext{})
			assertLevel(t, insights, tc.want)
		})
	}
}

// ── FD ───────────────────────────────────────────────────────────────────────

func TestFDSystemThresholds(t *testing.T) {
	cases := []struct {
		name string
		pct  float64
		want string
	}{
		{"below warn", 79.9, ""},
		{"at warn", 80.0, "WARN"},
		{"at crit", 90.0, "CRIT"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			insights := ApplyThresholds(res(models.FDInfo{UsedPct: tc.pct}), defaultThresh, platform.EnvBareMetal, platform.ContainerContext{})
			assertLevel(t, insights, tc.want)
		})
	}
}

func TestFDProcessWarn(t *testing.T) {
	fd := models.FDInfo{
		HotProcesses: []models.FDProcessInfo{
			{PID: 1, Name: "app", OpenFDs: 820, SoftLimit: 1024, UsedPct: 80.1},
		},
	}
	insights := ApplyThresholds(res(fd), defaultThresh, platform.EnvBareMetal, platform.ContainerContext{})
	if !hasLevel(insights, "WARN") {
		t.Error("expected WARN for process at 80.1% FD usage")
	}
}

func TestFDDeletedFilesWarn(t *testing.T) {
	fd := models.FDInfo{DeletedOpenSizeGB: 1.5}
	insights := ApplyThresholds(res(fd), defaultThresh, platform.EnvBareMetal, platform.ContainerContext{})
	if !hasLevel(insights, "WARN") {
		t.Error("expected WARN for 1.5 GB deleted open files")
	}
}

// ── Systemd ───────────────────────────────────────────────────────────────────

func TestSystemdFailedUnit(t *testing.T) {
	sys := models.SystemdInfo{Available: true, FailedUnits: []string{"foo.service"}}
	insights := ApplyThresholds(res(sys), defaultThresh, platform.EnvBareMetal, platform.ContainerContext{})
	if !hasLevel(insights, "CRIT") {
		t.Error("expected CRIT for failed systemd unit")
	}
}

func TestSystemdHealthy(t *testing.T) {
	sys := models.SystemdInfo{Available: true}
	insights := ApplyThresholds(res(sys), defaultThresh, platform.EnvBareMetal, platform.ContainerContext{})
	if len(insights) != 0 {
		t.Errorf("expected no insights for healthy systemd, got %+v", insights)
	}
}

func TestSystemdNotAvailable(t *testing.T) {
	// When systemd is not present the row should be hidden entirely (nil insights).
	// This covers macOS, Alpine, and containers that don't run systemd.
	// The previous behaviour of emitting INFO "systemd not present" was removed
	// because it creates noise on platforms where systemd is never expected.
	sys := models.SystemdInfo{Available: false}
	insights := ApplyThresholds(res(sys), defaultThresh, platform.EnvBareMetal, platform.ContainerContext{})
	for _, ins := range insights {
		if ins.Check == "Systemd" {
			t.Errorf("expected no Systemd insights when not available, got %+v", ins)
		}
	}
}

// ── Sysctl ────────────────────────────────────────────────────────────────────

func TestSysctlSomaxconnThresholds(t *testing.T) {
	cases := []struct {
		name string
		val  int
		want string
	}{
		{"ok", 4096, ""},
		{"warn", 800, "WARN"},
		{"crit", 256, "CRIT"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			insights := ApplyThresholds(res(models.SysctlInfo{NetSomaxconn: tc.val}), defaultThresh, platform.EnvBareMetal, platform.ContainerContext{})
			assertLevel(t, insights, tc.want)
		})
	}
}

func TestSysctlPIDCountThresholds(t *testing.T) {
	cases := []struct {
		name       string
		count, max int
		want       string
	}{
		{"ok", 100, 32768, ""},
		{"warn", 26215, 32768, "WARN"}, // 80%
		{"crit", 29492, 32768, "CRIT"}, // 90%
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s := models.SysctlInfo{PIDCount: tc.count, KernelPIDMax: tc.max, NetSomaxconn: 4096}
			insights := ApplyThresholds(res(s), defaultThresh, platform.EnvBareMetal, platform.ContainerContext{})
			assertLevel(t, insights, tc.want)
		})
	}
}

// ── SELinux ───────────────────────────────────────────────────────────────────

func TestSELinuxDenialsThresholds(t *testing.T) {
	cases := []struct {
		name  string
		count int
		want  string
	}{
		{"none", 0, "INFO"}, // dontaudit suppression warning fires when enforcing + zero denials
		{"at warn", 1, "WARN"},
		{"above warn", 5, "WARN"},
		{"at crit", 10, "CRIT"},
		{"above crit", 15, "CRIT"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			mac := models.KernelSecurityInfo{SELinuxPresent: true, SELinuxMode: "enforcing", SELinuxDenials: tc.count}
			insights := ApplyThresholds(res(mac), defaultThresh, platform.EnvBareMetal, platform.ContainerContext{})
			assertLevel(t, insights, tc.want)
		})
	}
}

func TestSELinuxAbsent(t *testing.T) {
	if runtime.GOOS == "linux" {
		t.Skip("Linux without SELinux/AppArmor correctly emits INFO; validated in integration tests")
	}
	// On macOS neither SELinux nor AppArmor is applicable.
	// KernelSec row should be hidden — no insights emitted.
	// On Linux without any security module, an INFO would be shown, but that
	// is exercised in integration tests on Linux, not here.
	mac := models.KernelSecurityInfo{SELinuxPresent: false, SELinuxDenials: 100}
	insights := ApplyThresholds(res(mac), defaultThresh, platform.EnvBareMetal, platform.ContainerContext{})
	for _, ins := range insights {
		if ins.Check == "KernelSec" {
			t.Errorf("expected no KernelSec insights on non-Linux platform, got %+v", ins)
		}
	}
}

func TestSELinuxDisabled(t *testing.T) {
	// SELinux compiled in but mode=disabled: on Linux this should produce INFO
	// ("kernel security module not enforced"). On macOS this test runs but the
	// runtime.GOOS guard returns nil — that's correct, since SELinux doesn't
	// apply to macOS. The Linux behaviour is validated in integration tests.
	mac := models.KernelSecurityInfo{SELinuxPresent: true, SELinuxMode: "disabled"}
	insights := ApplyThresholds(res(mac), defaultThresh, platform.EnvBareMetal, platform.ContainerContext{})
	// Just verify it doesn't panic and doesn't produce CRIT/WARN
	for _, ins := range insights {
		if ins.Level == "CRIT" || ins.Level == "WARN" {
			t.Errorf("unexpected %s insight for SELinux disabled: %+v", ins.Level, ins)
		}
	}
}

func TestKernelSecurityEnforcing(t *testing.T) {
	// SELinux enforcing with no denials should produce INFO about dontaudit
	// suppression — a proactive hint that hidden denials may exist.
	mac := models.KernelSecurityInfo{SELinuxPresent: true, SELinuxMode: "enforcing", SELinuxDenials: 0}
	insights := ApplyThresholds(res(mac), defaultThresh, platform.EnvBareMetal, platform.ContainerContext{})
	if !hasLevel(insights, "INFO") {
		t.Errorf("expected INFO dontaudit hint for enforcing SELinux with zero denials, got %+v", insights)
	}
}

func TestAppArmorUnknownAsNonRoot(t *testing.T) {
	// AppArmor present with mode=unknown means we couldn't read the
	// profiles file (typical non-root case). Must NOT be misclassified
	// as "no kernel security module enforcing" — that would be a false
	// system-fact claim. Should produce a privilege-aware INFO instead.
	mac := models.KernelSecurityInfo{AppArmorPresent: true, AppArmorMode: "unknown"}
	insights := ApplyThresholds(res(mac), defaultThresh, platform.EnvBareMetal, platform.ContainerContext{})
	if !hasLevel(insights, "INFO") {
		t.Fatalf("expected INFO insight for AppArmor unknown mode, got %+v", insights)
	}
	found := false
	for _, ins := range insights {
		if ins.Check == "KernelSec" && strings.Contains(ins.Message, "root") {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("expected privilege-aware message mentioning root, got %+v", insights)
	}
}

func TestAppArmorEnforcingHidesNoModuleMessage(t *testing.T) {
	// Sanity check the negative: when AppArmor is enforcing, the
	// "no kernel security module enforcing" message must not appear.
	mac := models.KernelSecurityInfo{AppArmorPresent: true, AppArmorMode: "enforce"}
	insights := ApplyThresholds(res(mac), defaultThresh, platform.EnvBareMetal, platform.ContainerContext{})
	for _, ins := range insights {
		if strings.Contains(ins.Message, "no kernel security module") {
			t.Errorf("AppArmor enforcing should not yield 'no module' message, got %+v", insights)
		}
	}
}

// ── Logs ─────────────────────────────────────────────────────────────────────

func TestJournalSizeThresholds(t *testing.T) {
	cases := []struct {
		name string
		gb   float64
		want string
	}{
		{"ok", 1.0, ""},
		{"at warn", 2.0, "WARN"},
		{"above warn", 3.0, "WARN"},
		{"at crit", 5.0, "CRIT"},
		{"above crit", 7.0, "CRIT"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			insights := ApplyThresholds(res(models.LogsInfo{JournalSizeGB: tc.gb}), defaultThresh, platform.EnvBareMetal, platform.ContainerContext{})
			assertLevel(t, insights, tc.want)
		})
	}
}

// ── Error result skipped ──────────────────────────────────────────────────────

func TestErrorResultSurfacedAsInfo(t *testing.T) {
	// Previously errored collectors were silently dropped (continue).
	// Now they must emit an INFO insight so the user knows the check didn't run.
	errMsg := "opening diskstats: permission denied"
	results := []runner.Result{
		{Name: "IO", Err: fmt.Errorf("%s", errMsg)},
	}
	insights := ApplyThresholds(results, defaultThresh, platform.EnvBareMetal, platform.ContainerContext{})
	if len(insights) != 1 {
		t.Fatalf("expected 1 INFO insight for errored collector, got %d: %+v", len(insights), insights)
	}
	if insights[0].Level != "INFO" {
		t.Errorf("level: got %q, want INFO", insights[0].Level)
	}
	if insights[0].Check != "IO" {
		t.Errorf("check: got %q, want IO", insights[0].Check)
	}
	if !contains(insights[0].Message, errMsg) {
		t.Errorf("message %q does not contain error %q", insights[0].Message, errMsg)
	}
}

func TestCheckNetworkGatewayStates(t *testing.T) {
	tests := []struct {
		name      string
		net       models.NetworkInfo
		wantLevel string
		wantMsg   string
	}{
		{
			name:      "both unreachable — truly offline",
			net:       models.NetworkInfo{GatewayPingMs: -1, InternetPingMs: -1},
			wantLevel: "CRIT",
			wantMsg:   "host appears offline",
		},
		{
			name:      "gateway blocks probes but internet flows — Zyxel case",
			net:       models.NetworkInfo{GatewayPingMs: -1, InternetPingMs: 14},
			wantLevel: "INFO",
			wantMsg:   "internet traffic is flowing",
		},
		{
			name:      "normal — both reachable",
			net:       models.NetworkInfo{GatewayPingMs: 5, InternetPingMs: 14},
			wantLevel: "",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			insights := checkNetwork(tt.net)
			if tt.wantLevel == "" {
				if len(insights) != 0 {
					t.Errorf("expected no insights, got %+v", insights)
				}
				return
			}
			if len(insights) == 0 {
				t.Fatalf("expected insight with level %s, got none", tt.wantLevel)
			}
			if insights[0].Level != tt.wantLevel {
				t.Errorf("level: got %q, want %q", insights[0].Level, tt.wantLevel)
			}
			if tt.wantMsg != "" && !contains(insights[0].Message, tt.wantMsg) {
				t.Errorf("message %q does not contain %q", insights[0].Message, tt.wantMsg)
			}
		})
	}
}

func contains(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || len(substr) == 0 ||
		(func() bool {
			for i := 0; i <= len(s)-len(substr); i++ {
				if s[i:i+len(substr)] == substr {
					return true
				}
			}
			return false
		})())
}

// ── LVM ──────────────────────────────────────────────────────────────────────

func TestCheckLVMThinPools(t *testing.T) {
	pool := func(dataPct, metaPct float64) models.LVMInfo {
		return models.LVMInfo{
			ThinPools: []models.LVMThinPool{
				{Name: "data", VG: "pve", DataPct: dataPct, MetaPct: metaPct, SizeGB: 100},
			},
		}
	}

	cases := []struct {
		name      string
		dataPct   float64
		metaPct   float64
		wantLevel string
	}{
		{"healthy — no insight", 50, 10, ""},
		{"data at WARN threshold (80%)", 80, 10, "WARN"},
		{"data at CRIT threshold (91%)", 91, 10, "CRIT"},
		{"meta at WARN threshold (50%)", 40, 50, "WARN"},
		{"meta at CRIT threshold (76%)", 40, 76, "CRIT"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			insights := checkLVM(pool(tc.dataPct, tc.metaPct))
			assertLevel(t, insights, tc.wantLevel)
		})
	}
}

func TestCheckLVMVGFreeSpace(t *testing.T) {
	vg := func(sizeGB, freeGB float64, mounted bool) models.LVMInfo {
		freePct := 0.0
		if sizeGB > 0 {
			freePct = freeGB / sizeGB * 100
		}
		return models.LVMInfo{
			VGs: []models.LVMVG{
				{Name: "myvg", SizeGB: sizeGB, FreeGB: freeGB, FreePct: freePct, HasMountedLV: mounted},
			},
		}
	}

	cases := []struct {
		name      string
		sizeGB    float64
		freeGB    float64
		mounted   bool
		wantLevel string
	}{
		{"healthy — plenty free", 100, 40, true, ""},
		{"WARN — 91% used (9% free)", 100, 9, true, "WARN"},
		{"CRIT — 99% used (1% free)", 100, 1, true, "CRIT"},
		{"no mounted LVs — inactive VG — always INFO", 100, 1, false, "INFO"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			insights := checkLVM(vg(tc.sizeGB, tc.freeGB, tc.mounted))
			assertLevel(t, insights, tc.wantLevel)
		})
	}
}

func TestCheckLVMMissingPVs(t *testing.T) {
	vgWithMissing := models.LVMInfo{
		VGs: []models.LVMVG{
			{Name: "myvg", SizeGB: 100, FreeGB: 50, FreePct: 50, HasMountedLV: true, MissingPVs: 1},
		},
	}
	vgHealthy := models.LVMInfo{
		VGs: []models.LVMVG{
			{Name: "myvg", SizeGB: 100, FreeGB: 50, FreePct: 50, HasMountedLV: true, MissingPVs: 0},
		},
	}

	t.Run("missing PV triggers CRIT", func(t *testing.T) {
		insights := checkLVM(vgWithMissing)
		assertLevel(t, insights, "CRIT")
	})

	t.Run("no missing PVs — no insight", func(t *testing.T) {
		insights := checkLVM(vgHealthy)
		assertLevel(t, insights, "")
	})
}

func TestCheckLVMSnapshots(t *testing.T) {
	snap := func(dataPct float64) models.LVMInfo {
		return models.LVMInfo{
			Snapshots: []models.LVMSnapshot{
				{Name: "snap0", VG: "pve", Origin: "vm-100-disk-0", DataPct: dataPct},
			},
		}
	}

	cases := []struct {
		name      string
		dataPct   float64
		wantLevel string
	}{
		{"healthy snapshot — no insight", 50, ""},
		{"snapshot at WARN (80%)", 80, "WARN"},
		{"snapshot at CRIT (95%)", 95, "CRIT"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			insights := checkLVM(snap(tc.dataPct))
			assertLevel(t, insights, tc.wantLevel)
		})
	}
}

func TestCheckLVMEmpty(t *testing.T) {
	// No LVM configured — should produce no insights
	insights := checkLVM(models.LVMInfo{})
	if len(insights) != 0 {
		t.Errorf("expected no insights for empty LVMInfo, got %d: %+v", len(insights), insights)
	}
}

// ── Proxmox VE false-positive suppression (BUG-016 … BUG-019) ────────────────

// hasInsight reports whether any insight matches the given level and a substring
// of its message — used to assert PVE-specific downgrades precisely.
func hasInsight(insights []models.Insight, level, msgSubstr string) bool {
	for _, ins := range insights {
		if ins.Level == level && strings.Contains(ins.Message, msgSubstr) {
			return true
		}
	}
	return false
}

// BUG-016: PVE service ports 8006/3128/111 must surface as INFO, never WARN.
func TestPVEServicePortsSuppressed(t *testing.T) {
	ports := []models.PortEntry{
		{Port: 8006, Protocol: "tcp", Process: "pvedaemon"},
		{Port: 3128, Protocol: "tcp", Process: "spiceproxy"},
		{Port: 111, Protocol: "tcp", Process: "rpcbind"},
	}

	// On PVE: no WARN about these ports, and an INFO "PVE service port" line.
	pve := models.SecurityInfo{IsPVE: true, ListeningPorts: ports}
	got := ApplyThresholds(res(pve), defaultThresh, platform.EnvBareMetal, platform.ContainerContext{})
	if hasInsight(got, "WARN", "unexpected port") {
		t.Errorf("PVE host should not WARN on 8006/3128/111, got %+v", got)
	}
	if !hasInsight(got, "INFO", "PVE service port") {
		t.Errorf("expected INFO PVE service port line, got %+v", got)
	}

	// Non-PVE control: the same ports remain a WARN.
	nonPVE := models.SecurityInfo{IsPVE: false, ListeningPorts: ports}
	gotNon := ApplyThresholds(res(nonPVE), defaultThresh, platform.EnvBareMetal, platform.ContainerContext{})
	if !hasInsight(gotNon, "WARN", "unexpected port") {
		t.Errorf("non-PVE host should WARN on 8006/3128/111, got %+v", gotNon)
	}
}

// BUG-017: an empty ruleset with pve-firewall active is INFO, not WARN.
func TestPVEFirewallNoFalsePositive(t *testing.T) {
	pve := models.FirewallInfo{Available: true, Backend: "nftables", Active: false, PVEFirewallActive: true}
	got := checkFirewall(pve)
	if hasLevel(got, "WARN") {
		t.Errorf("pve-firewall active should suppress the unprotected WARN, got %+v", got)
	}
	if !hasInsight(got, "INFO", "pve-firewall") {
		t.Errorf("expected INFO mentioning pve-firewall, got %+v", got)
	}

	// Control: same empty ruleset without pve-firewall stays a WARN.
	plain := models.FirewallInfo{Available: true, Backend: "nftables", Active: false}
	if !hasLevel(checkFirewall(plain), "WARN") {
		t.Errorf("empty ruleset without pve-firewall should WARN, got %+v", checkFirewall(plain))
	}
}

// BUG-018: PermitRootLogin=yes is INFO on PVE (required), CRIT elsewhere.
func TestPVESSHRootLoginDowngraded(t *testing.T) {
	pve := models.SecurityInfo{IsPVE: true, SSHPermitRoot: true}
	got := ApplyThresholds(res(pve), defaultThresh, platform.EnvBareMetal, platform.ContainerContext{})
	if hasInsight(got, "CRIT", "root login") || hasInsight(got, "CRIT", "permits root") {
		t.Errorf("PVE host should not CRIT on root SSH, got %+v", got)
	}
	if !hasInsight(got, "INFO", "required for PVE management") {
		t.Errorf("expected INFO about PVE-required root SSH, got %+v", got)
	}

	// Non-PVE control: still CRIT.
	nonPVE := models.SecurityInfo{IsPVE: false, SSHPermitRoot: true}
	gotNon := ApplyThresholds(res(nonPVE), defaultThresh, platform.EnvBareMetal, platform.ContainerContext{})
	if !hasInsight(gotNon, "CRIT", "root login") {
		t.Errorf("non-PVE host should CRIT on root SSH, got %+v", gotNon)
	}
}

// BUG-019: no backup must be CRIT (not WARN) so it bubbles into the PVE summary.
// The node must have a backable (non-template) guest — BackupStatuses has one
// entry per such guest; a fresh/template-only node with nothing to back up no
// longer CRITs (#119 false-positive fix).
func TestPVENoBackupIsCrit(t *testing.T) {
	p := models.PVEInfo{IsPVE: true, QuorumOK: true, BackupAgeDays: -1,
		BackupStatuses: []models.PVEBackupStatus{{VMID: 100, Name: "vm", LastBackupDays: -1}}}
	got := checkPVE(p)
	if !hasInsight(got, "CRIT", "no successful backup") {
		t.Errorf("no backup on PVE must be CRIT, got %+v", got)
	}
	if hasInsight(got, "WARN", "no successful backup") {
		t.Errorf("no-backup finding must not remain WARN, got %+v", got)
	}
}

func TestIsPVEServicePort(t *testing.T) {
	for _, p := range []int{8006, 3128, 111} {
		if !IsPVEServicePort(p) {
			t.Errorf("port %d should be a PVE service port", p)
		}
	}
	for _, p := range []int{22, 80, 443, 9090} {
		if IsPVEServicePort(p) {
			t.Errorf("port %d should not be a PVE service port", p)
		}
	}
}

// Run-queue saturation: WARN at ≥2× cores, CRIT at ≥4× cores, silent below.
func TestCheckCPURunQueueSaturation(t *testing.T) {
	cases := []struct {
		name      string
		runQueue  int
		numCPU    int
		wantLevel string // "" = no run-queue insight expected
	}{
		{"healthy single runnable", 1, 4, ""},
		{"at core count", 4, 4, ""},
		{"just below warn", 7, 4, ""},
		{"warn at 2x", 8, 4, "WARN"},
		{"warn band", 12, 4, "WARN"},
		{"crit at 4x", 16, 4, "CRIT"},
		{"zero runqueue (non-linux)", 0, 4, ""},
		{"zero cpu guarded", 8, 0, ""},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			// LoadAvg1 set to the core count (100% load ratio) so the run-queue
			// reading is load-corroborated — this test exercises the run-queue
			// thresholds, not the observer-effect guard (covered separately).
			cpu := models.CPUInfo{NumCPU: tc.numCPU, RunQueue: tc.runQueue, LoadAvg1: float64(tc.numCPU)}
			got := checkCPU(cpu, defaultThresh)
			has := func(level string) bool {
				for _, ins := range got {
					if ins.Check == "CPU Load/RunQueue" && ins.Level == level {
						return true
					}
				}
				return false
			}
			if tc.wantLevel == "" {
				if has("WARN") || has("CRIT") {
					t.Errorf("%s: expected no CPU/RunQueue insight, got %+v", tc.name, got)
				}
				return
			}
			if !has(tc.wantLevel) {
				t.Errorf("%s: expected CPU/RunQueue %s, got %+v", tc.name, tc.wantLevel, got)
			}
		})
	}
}

// Context-switch rate and blocked count surface as supporting hints, not their own threshold.
func TestRunQueueHintsIncludeContext(t *testing.T) {
	cpu := models.CPUInfo{NumCPU: 2, RunQueue: 8, LoadAvg1: 2.0, ContextSwitchRate: 42000, ProcsBlocked: 3}
	got := checkCPU(cpu, defaultThresh)
	var hints []string
	for _, ins := range got {
		if ins.Check == "CPU Load/RunQueue" {
			hints = ins.Hints
		}
	}
	if len(hints) == 0 {
		t.Fatal("expected CPU/RunQueue insight with hints")
	}
	joined := strings.Join(hints, "\n")
	if !strings.Contains(joined, "context switches/s") {
		t.Errorf("expected context-switch hint, got %v", hints)
	}
	if !strings.Contains(joined, "blocked on I/O") {
		t.Errorf("expected blocked-task hint, got %v", hints)
	}
}

// Single-core hosts must read "1 CPU", not "1 CPUs".
func TestRunQueueSingleCPUGrammar(t *testing.T) {
	cpu := models.CPUInfo{NumCPU: 1, RunQueue: 4, LoadAvg1: 1.5} // 4 >= 4*1 → CRIT; load corroborates
	got := checkCPU(cpu, defaultThresh)
	var msg string
	for _, ins := range got {
		if ins.Check == "CPU Load/RunQueue" {
			msg = ins.Message
		}
	}
	if msg == "" {
		t.Fatal("expected a CPU/RunQueue insight")
	}
	if strings.Contains(msg, "1 CPUs") {
		t.Errorf("bad pluralization on single-core host: %q", msg)
	}
	if !strings.Contains(msg, "1 CPU ") {
		t.Errorf("expected 'on 1 CPU', got: %q", msg)
	}
}

// btrfs device errors: read/write I/O = CRIT (failing device), corruption-only = WARN.
func btrfsInsight(disk models.DiskInfo) (level, msg string, found bool) {
	for _, ins := range checkDiskExtras(disk) {
		if ins.Check == "Disk" && strings.Contains(ins.Message, "btrfs") {
			return ins.Level, ins.Message, true
		}
	}
	return "", "", false
}

func TestCheckDiskExtrasBtrfsIOErrorsCrit(t *testing.T) {
	disk := models.DiskInfo{BtrfsVolumes: []models.BtrfsVolume{{
		MountPoint: "/", Status: "errors",
		Devices: []models.BtrfsDev{{Path: "/dev/sda", ReadErrs: 0, WriteErrs: 5}},
	}}}
	level, msg, found := btrfsInsight(disk)
	if !found || level != "CRIT" {
		t.Fatalf("btrfs write I/O errors should be CRIT, got level=%q found=%v", level, found)
	}
	if !strings.Contains(msg, "I/O error") {
		t.Errorf("unexpected message: %q", msg)
	}
}

func TestCheckDiskExtrasBtrfsCorruptionWarn(t *testing.T) {
	disk := models.DiskInfo{BtrfsVolumes: []models.BtrfsVolume{{
		MountPoint: "/data", Status: "errors",
		Devices: []models.BtrfsDev{{Path: "/dev/sdb", CorruptErrs: 3}},
	}}}
	level, msg, found := btrfsInsight(disk)
	if !found || level != "WARN" {
		t.Fatalf("corruption-only should be WARN, got level=%q found=%v", level, found)
	}
	if !strings.Contains(msg, "scrub-correctable") {
		t.Errorf("unexpected message: %q", msg)
	}
}

func TestCheckDiskExtrasBtrfsIOWinsOverCorruption(t *testing.T) {
	// A device with both I/O and corruption errors → CRIT (I/O is the worse signal).
	disk := models.DiskInfo{BtrfsVolumes: []models.BtrfsVolume{{
		MountPoint: "/", Status: "errors",
		Devices: []models.BtrfsDev{{Path: "/dev/sda", ReadErrs: 2, CorruptErrs: 9}},
	}}}
	if level, _, _ := btrfsInsight(disk); level != "CRIT" {
		t.Errorf("I/O + corruption should be CRIT, got %q", level)
	}
}

func TestCheckDiskExtrasBtrfsMissingStillCrit(t *testing.T) {
	// Regression: missing-device DEGRADED path is unchanged.
	disk := models.DiskInfo{BtrfsVolumes: []models.BtrfsVolume{{
		MountPoint: "/", MissingDevs: 1, Status: "degraded",
	}}}
	if level, msg, found := btrfsInsight(disk); !found || level != "CRIT" || !strings.Contains(msg, "DEGRADED") {
		t.Errorf("missing device should stay CRIT/DEGRADED, got level=%q msg=%q", level, msg)
	}
}
