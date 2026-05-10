package analysis

import (
	"fmt"
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
			insights := ApplyThresholds(res(models.CPUInfo{LoadPct: tc.loadPct, NumCPU: 4}), defaultThresh, platform.EnvBareMetal)
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
			insights := ApplyThresholds(res(models.MemoryInfo{UsedPct: tc.pct, TotalGB: 16}), defaultThresh, platform.EnvBareMetal)
			assertLevel(t, insights, tc.want)
		})
	}
}

func TestMemoryOverCommitted(t *testing.T) {
	insights := ApplyThresholds(res(models.MemoryInfo{OverCommitted: true, TotalGB: 16}), defaultThresh, platform.EnvBareMetal)
	if !hasLevel(insights, "CRIT") {
		t.Error("expected CRIT for OverCommitted=true")
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
			insights := ApplyThresholds(res(m), defaultThresh, platform.EnvBareMetal)
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
			insights := ApplyThresholds(res(d), defaultThresh, platform.EnvBareMetal)
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
			insights := ApplyThresholds(res(d), defaultThresh, platform.EnvBareMetal)
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
			insights := ApplyThresholds(res(models.SwapInfo{UsedPct: tc.pct}), defaultThresh, platform.EnvBareMetal)
			assertLevel(t, insights, tc.want)
		})
	}
}

func TestSwapActivityThresholds(t *testing.T) {
	cases := []struct {
		name      string
		pagesIn   float64
		pagesOut  float64
		wantLevel string
	}{
		{"no activity", 0, 0, ""},
		{"any swap in warn", 1, 0, "WARN"},
		{"any swap out warn", 0, 1, "WARN"},
		{"crit swap in", 101, 0, "CRIT"},
		{"crit swap out", 0, 101, "CRIT"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s := models.SwapInfo{PagesInPerSec: tc.pagesIn, PagesOutPerSec: tc.pagesOut}
			insights := ApplyThresholds(res(s), defaultThresh, platform.EnvBareMetal)
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
			insights := ApplyThresholds(res(s), defaultThresh, platform.EnvBareMetal)
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
			insights := ApplyThresholds(res(s), defaultThresh, platform.EnvBareMetal)
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
			insights := ApplyThresholds(res(io), defaultThresh, platform.EnvBareMetal)
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
			insights := ApplyThresholds(res(io), thresh, platform.EnvBareMetal)
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
			insights := ApplyThresholds(res(io), thresh, platform.EnvAWSEBS)
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
			insights := ApplyThresholds(res(models.NetworkInfo{GatewayPingMs: tc.ms}), defaultThresh, platform.EnvBareMetal)
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
		{"ok", 50, ""},
		{"warn", 500, "WARN"},
		{"crit", 1500, "CRIT"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			insights := ApplyThresholds(res(models.NetworkInfo{DNSResolvesMs: tc.ms}), defaultThresh, platform.EnvBareMetal)
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
			insights := ApplyThresholds(res(models.NetworkInfo{CloseWaitCount: tc.count}), defaultThresh, platform.EnvBareMetal)
			assertLevel(t, insights, tc.want)
		})
	}
}

// ── Clock ────────────────────────────────────────────────────────────────────

func TestClockNilPointer(t *testing.T) {
	results := []runner.Result{{Name: "Clock", Data: (*models.ClockInfo)(nil)}}
	insights := ApplyThresholds(results, defaultThresh, platform.EnvBareMetal)
	if len(insights) != 0 {
		t.Errorf("expected no insights for nil *ClockInfo, got %+v", insights)
	}
}

func TestClockNotSynced(t *testing.T) {
	insights := ApplyThresholds(res(models.ClockInfo{Synced: false, OffsetMs: -1}), defaultThresh, platform.EnvBareMetal)
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
			insights := ApplyThresholds(res(models.ClockInfo{Synced: true, OffsetMs: tc.offsetMs}), defaultThresh, platform.EnvBareMetal)
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
			insights := ApplyThresholds(res(models.FDInfo{UsedPct: tc.pct}), defaultThresh, platform.EnvBareMetal)
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
	insights := ApplyThresholds(res(fd), defaultThresh, platform.EnvBareMetal)
	if !hasLevel(insights, "WARN") {
		t.Error("expected WARN for process at 80.1% FD usage")
	}
}

func TestFDDeletedFilesWarn(t *testing.T) {
	fd := models.FDInfo{DeletedOpenSizeGB: 1.5}
	insights := ApplyThresholds(res(fd), defaultThresh, platform.EnvBareMetal)
	if !hasLevel(insights, "WARN") {
		t.Error("expected WARN for 1.5 GB deleted open files")
	}
}

// ── Systemd ───────────────────────────────────────────────────────────────────

func TestSystemdFailedUnit(t *testing.T) {
	sys := models.SystemdInfo{Available: true, FailedUnits: []string{"foo.service"}}
	insights := ApplyThresholds(res(sys), defaultThresh, platform.EnvBareMetal)
	if !hasLevel(insights, "CRIT") {
		t.Error("expected CRIT for failed systemd unit")
	}
}

func TestSystemdHealthy(t *testing.T) {
	sys := models.SystemdInfo{Available: true}
	insights := ApplyThresholds(res(sys), defaultThresh, platform.EnvBareMetal)
	if len(insights) != 0 {
		t.Errorf("expected no insights for healthy systemd, got %+v", insights)
	}
}

func TestSystemdNotAvailable(t *testing.T) {
	// On Alpine, macOS, and most containers systemd doesn't exist.
	// Should produce INFO insight, not silently fall through to OK
	// which would mislead users into thinking systemd is healthy.
	sys := models.SystemdInfo{Available: false}
	insights := ApplyThresholds(res(sys), defaultThresh, platform.EnvBareMetal)
	if !hasLevel(insights, "INFO") {
		t.Errorf("expected INFO insight when systemd not available, got %+v", insights)
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
			insights := ApplyThresholds(res(models.SysctlInfo{NetSomaxconn: tc.val}), defaultThresh, platform.EnvBareMetal)
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
			insights := ApplyThresholds(res(s), defaultThresh, platform.EnvBareMetal)
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
		{"none", 0, ""},
		{"at warn", 1, "WARN"},
		{"above warn", 5, "WARN"},
		{"at crit", 10, "CRIT"},
		{"above crit", 15, "CRIT"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			mac := models.KernelSecurityInfo{SELinuxPresent: true, SELinuxMode: "enforcing", SELinuxDenials: tc.count}
			insights := ApplyThresholds(res(mac), defaultThresh, platform.EnvBareMetal)
			assertLevel(t, insights, tc.want)
		})
	}
}

func TestSELinuxAbsent(t *testing.T) {
	mac := models.KernelSecurityInfo{SELinuxPresent: false, SELinuxDenials: 100}
	insights := ApplyThresholds(res(mac), defaultThresh, platform.EnvBareMetal)
	// Now expects an INFO insight when no kernel security module is enforcing,
	// rather than no insights at all (which previously fell through to OK and
	// misled users on Alpine/macOS/containers into thinking security was active).
	if !hasLevel(insights, "INFO") {
		t.Errorf("expected INFO insight when no kernel security module is enforcing, got %+v", insights)
	}
}

func TestSELinuxDisabled(t *testing.T) {
	// SELinux compiled in but mode=disabled should also produce INFO,
	// since "present but disabled" means no policy is being enforced.
	mac := models.KernelSecurityInfo{SELinuxPresent: true, SELinuxMode: "disabled"}
	insights := ApplyThresholds(res(mac), defaultThresh, platform.EnvBareMetal)
	if !hasLevel(insights, "INFO") {
		t.Errorf("expected INFO insight for SELinux in disabled mode, got %+v", insights)
	}
}

func TestKernelSecurityEnforcing(t *testing.T) {
	// SELinux enforcing with no denials should produce no insight (healthy state).
	mac := models.KernelSecurityInfo{SELinuxPresent: true, SELinuxMode: "enforcing", SELinuxDenials: 0}
	insights := ApplyThresholds(res(mac), defaultThresh, platform.EnvBareMetal)
	if len(insights) != 0 {
		t.Errorf("expected no insights for healthy enforcing SELinux, got %+v", insights)
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
			insights := ApplyThresholds(res(models.LogsInfo{JournalSizeGB: tc.gb}), defaultThresh, platform.EnvBareMetal)
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
	insights := ApplyThresholds(results, defaultThresh, platform.EnvBareMetal)
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
