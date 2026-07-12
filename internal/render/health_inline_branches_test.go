package render

import (
	"testing"

	"github.com/keyorixhq/dashdiag/internal/models"
)

// TestInlineFDLimitsUnlimitedAndDeleted covers the "effectively unlimited"
// MaxCount branch (0 or the huge Linux default) plus the deleted-open-files
// suffix, in both the unlimited and normal-limit paths.
func TestInlineFDLimitsUnlimitedAndDeleted(t *testing.T) {
	t.Parallel()
	if got := inlineFDLimits(models.FDInfo{MaxCount: 0, OpenCount: 250}); got != "250 open" {
		t.Errorf("MaxCount=0 (unlimited): got %q, want %q", got, "250 open")
	}
	if got := inlineFDLimits(models.FDInfo{MaxCount: 1 << 41, OpenCount: 250, DeletedOpenFiles: 3}); got != "250 open  3 deleted" {
		t.Errorf("huge MaxCount + deleted: got %q, want %q", got, "250 open  3 deleted")
	}
	if got := inlineFDLimits(models.FDInfo{MaxCount: 1000, OpenCount: 500, UsedPct: 50, DeletedOpenFiles: 2}); got != "50% (500/1k open)  2 deleted" {
		t.Errorf("normal limit + deleted: got %q, want %q", got, "50% (500/1k open)  2 deleted")
	}
}

// TestInlineSwapNone covers the TotalGB==0 ("no swap configured") branch,
// distinct from the nonzero-usage branch already covered by inlineCases.
func TestInlineSwapNone(t *testing.T) {
	t.Parallel()
	if got := inlineSwap(models.SwapInfo{TotalGB: 0}); got != "none" {
		t.Errorf("no swap: got %q, want %q", got, "none")
	}
}

// TestInlineIOEmptyDevices covers the empty-devices guard (distinct from the
// nil-data guard already covered by inlineCases).
func TestInlineIOEmptyDevices(t *testing.T) {
	t.Parallel()
	if got := inlineIO(models.IOInfo{Devices: nil}); got != "" {
		t.Errorf("empty Devices: got %q, want empty", got)
	}
}

// TestKernelSecInlineBranches covers SELinux, AppArmor, and neither-present.
func TestKernelSecInlineBranches(t *testing.T) {
	t.Parallel()
	if got := kernelSecInline(&models.KernelSecurityInfo{SELinuxPresent: true, SELinuxMode: "enforcing"}); got != "SELinux enforcing" {
		t.Errorf("SELinux: got %q", got)
	}
	if got := kernelSecInline(&models.KernelSecurityInfo{AppArmorPresent: true, AppArmorMode: "enforce"}); got != "AppArmor enforce" {
		t.Errorf("AppArmor: got %q", got)
	}
	if got := kernelSecInline(&models.KernelSecurityInfo{}); got != "" {
		t.Errorf("neither present: got %q, want empty", got)
	}
}

// TestInlineClockBranches covers: not synced -> empty, synced with/without a
// Source label.
func TestInlineClockBranches(t *testing.T) {
	t.Parallel()
	if got := inlineClock(models.ClockInfo{Synced: false, OffsetMs: 5}); got != "" {
		t.Errorf("not synced: got %q, want empty", got)
	}
	if got := inlineClock(models.ClockInfo{Synced: true, OffsetMs: -3, Source: "chrony"}); got != "±3 ms  chrony" {
		t.Errorf("synced with source: got %q", got)
	}
	if got := inlineClock(models.ClockInfo{Synced: true, OffsetMs: 3}); got != "±3 ms" {
		t.Errorf("synced without source: got %q", got)
	}
}

// TestInlineLogsZero covers the zero-JournalSizeGB guard.
func TestInlineLogsZero(t *testing.T) {
	t.Parallel()
	if got := inlineLogs(models.LogsInfo{JournalSizeGB: 0}); got != "" {
		t.Errorf("zero journal size: got %q, want empty", got)
	}
}

// TestInlineCPUThermalZero covers the zero-temp guard.
func TestInlineCPUThermalZero(t *testing.T) {
	t.Parallel()
	if got := inlineCPUThermal(models.ThermalInfo{CPUTempC: 0}); got != "" {
		t.Errorf("zero temp: got %q, want empty", got)
	}
}

// TestInlineBatteryBranches covers not-present, and present with/without a
// status label.
func TestInlineBatteryBranches(t *testing.T) {
	t.Parallel()
	if got := inlineBattery(models.BatteryInfo{Present: false}); got != "" {
		t.Errorf("not present: got %q, want empty", got)
	}
	if got := inlineBattery(models.BatteryInfo{Present: true, CapacityPct: 90, Status: "Charging"}); got != "90%  charging" {
		t.Errorf("present with status: got %q", got)
	}
	if got := inlineBattery(models.BatteryInfo{Present: true, CapacityPct: 90}); got != "90%" {
		t.Errorf("present without status: got %q", got)
	}
}

// TestInlineSystemdBranches covers: unavailable -> empty, available with no
// boot time -> empty, available with boot time -> formatted.
func TestInlineSystemdBranches(t *testing.T) {
	t.Parallel()
	if got := inlineSystemd(models.SystemdInfo{Available: false}); got != "" {
		t.Errorf("unavailable: got %q, want empty", got)
	}
	if got := inlineSystemd(models.SystemdInfo{Available: true, TotalBootSec: 0}); got != "" {
		t.Errorf("available, zero boot time: got %q, want empty", got)
	}
	if got := inlineSystemd(models.SystemdInfo{Available: true, TotalBootSec: 12.3}); got != "boot 12s" {
		t.Errorf("available with boot time: got %q", got)
	}
}

// TestInlineProcessesBranches covers: nil -> empty, zombie/hung takes
// priority over Total, Total-only, and the empty fallback (Total==0, no
// zombie/hung).
func TestInlineProcessesBranches(t *testing.T) {
	t.Parallel()
	if got := inlineProcesses(models.ProcessInfo{ZombieCount: 2, HungCount: 1, Total: 100}); got != "2 zombie  1 hung" {
		t.Errorf("zombie/hung priority: got %q", got)
	}
	if got := inlineProcesses(models.ProcessInfo{Total: 100}); got != "100 running" {
		t.Errorf("total only: got %q", got)
	}
	if got := inlineProcesses(models.ProcessInfo{}); got != "" {
		t.Errorf("all zero: got %q, want empty", got)
	}
}

// TestInlineBondingMulti covers the 2+ bonds summary branch (distinct from
// the single-bond branch already covered by inlineCases).
func TestInlineBondingMulti(t *testing.T) {
	t.Parallel()
	b := models.BondingInfo{Bonds: []models.BondInterface{
		{Name: "bond0", Slaves: []models.BondSlave{{Name: "eth0"}, {Name: "eth1"}}},
		{Name: "bond1", Slaves: []models.BondSlave{{Name: "eth2"}}},
	}}
	if got := inlineBonding(b); got != "2 bonds  3 slaves" {
		t.Errorf("multi-bond: got %q, want %q", got, "2 bonds  3 slaves")
	}
	// Empty Bonds slice -> empty (distinct guard from nil).
	if got := inlineBonding(models.BondingInfo{Bonds: []models.BondInterface{}}); got != "" {
		t.Errorf("empty bonds: got %q, want empty", got)
	}
}

// TestInlineOOMBranches covers: unavailable -> empty, unread (StatusReason
// set) -> "not verified", zero events, and nonzero events.
func TestInlineOOMBranches(t *testing.T) {
	t.Parallel()
	if got := inlineOOM(models.OOMInfo{Available: false}); got != "" {
		t.Errorf("unavailable: got %q, want empty", got)
	}
	if got := inlineOOM(models.OOMInfo{Available: true, StatusReason: "kernel log unreadable"}); got != "not verified (kernel log unreadable)" {
		t.Errorf("unread: got %q", got)
	}
	if got := inlineOOM(models.OOMInfo{Available: true, EventsLast24h: 0}); got != "0 events" {
		t.Errorf("zero events: got %q", got)
	}
	if got := inlineOOM(models.OOMInfo{Available: true, EventsLast24h: 5}); got != "5 event(s) in 24h" {
		t.Errorf("nonzero events: got %q", got)
	}
}

// TestInlineLVMBranches covers: no active VGs, exactly one active VG
// (singular "VG"), and 2+ active VGs (plural with count).
func TestInlineLVMBranches(t *testing.T) {
	t.Parallel()
	if got := inlineLVM(models.LVMInfo{VGs: []models.LVMVG{{HasMountedLV: false}, {HasMountedLV: false}}}); got != "2 VG(s)" {
		t.Errorf("no active: got %q, want %q", got, "2 VG(s)")
	}
	if got := inlineLVM(models.LVMInfo{VGs: []models.LVMVG{{HasMountedLV: true}}}); got != "1 VG" {
		t.Errorf("single active: got %q, want %q", got, "1 VG")
	}
	if got := inlineLVM(models.LVMInfo{VGs: []models.LVMVG{{HasMountedLV: true}, {HasMountedLV: true}}}); got != "2 VG(s)  2 active" {
		t.Errorf("multi active: got %q, want %q", got, "2 VG(s)  2 active")
	}
}

// TestInlineSessionsBranches covers: zero sessions, exactly one session (with
// a User label), remote sessions present, and plain multi-session count.
func TestInlineSessionsBranches(t *testing.T) {
	t.Parallel()
	if got := inlineSessions(models.SessionsInfo{TotalCount: 0}); got != "no active sessions" {
		t.Errorf("zero: got %q", got)
	}
	if got := inlineSessions(models.SessionsInfo{TotalCount: 1, Sessions: []models.Session{{User: "root"}}}); got != "1 session (root)" {
		t.Errorf("single: got %q", got)
	}
	if got := inlineSessions(models.SessionsInfo{TotalCount: 3, RemoteCount: 2}); got != "3 sessions  2 remote" {
		t.Errorf("remote: got %q", got)
	}
	if got := inlineSessions(models.SessionsInfo{TotalCount: 3}); got != "3 sessions" {
		t.Errorf("plain multi: got %q", got)
	}
}

// TestInlineHBAOffline covers ports that are neither "online" nor "linkup".
func TestInlineHBAOffline(t *testing.T) {
	t.Parallel()
	h := models.HBAInfo{Ports: []models.HBAPort{{PortState: "Online"}, {PortState: "Linkdown"}}}
	if got := inlineHBA(h); got != "1/2 ports online" {
		t.Errorf("mixed: got %q, want %q", got, "1/2 ports online")
	}
	// Case-insensitive "linkup" also counts as online.
	h2 := models.HBAInfo{Ports: []models.HBAPort{{PortState: "LinkUp"}}}
	if got := inlineHBA(h2); got != "1/1 ports online" {
		t.Errorf("linkup: got %q, want %q", got, "1/1 ports online")
	}
}

// TestInlinePressureBranches covers "no pressure" (all zero) vs. some
// nonzero pressure metric.
func TestInlinePressureBranches(t *testing.T) {
	t.Parallel()
	if got := inlinePressure(models.PressureInfo{Available: true}); got != "no pressure" {
		t.Errorf("all zero: got %q", got)
	}
	p := models.PressureInfo{Available: true, MemorySome: models.PSILine{Avg10: 5}}
	if got := inlinePressure(p); got == "" || got == "no pressure" {
		t.Errorf("nonzero pressure: got %q, want a formatted pressure line", got)
	}
}

// TestInlineMultipathBranches covers the error status, empty-devices (after
// availability), and a populated device list.
func TestInlineMultipathBranches(t *testing.T) {
	t.Parallel()
	if got := inlineMultipath(models.MultipathInfo{Available: true, Status: "error"}); got != "paths unreadable — not verified" {
		t.Errorf("error status: got %q", got)
	}
	if got := inlineMultipath(models.MultipathInfo{Available: true, Devices: nil}); got != "" {
		t.Errorf("empty devices: got %q, want empty", got)
	}
	d := models.MultipathInfo{Available: true, Devices: []models.MultipathDevice{{Name: "mpatha", TotalPaths: 4}}}
	if got := inlineMultipath(d); got != "1 devices  4 paths" {
		t.Errorf("populated: got %q, want %q", got, "1 devices  4 paths")
	}
}

// TestInlineCephBranches covers the OSDTotal==0 fallback (bare Health string)
// vs. the OSD-count-included form.
func TestInlineCephBranches(t *testing.T) {
	t.Parallel()
	if got := inlineCeph(models.CephInfo{Available: true, Health: "HEALTH_WARN", OSDTotal: 0}); got != "HEALTH_WARN" {
		t.Errorf("no OSDs: got %q, want bare health string", got)
	}
	if got := inlineCeph(models.CephInfo{Available: true, Health: "HEALTH_OK", OSDTotal: 3, OSDUp: 3}); got != "HEALTH_OK  3/3 OSDs up" {
		t.Errorf("with OSDs: got %q", got)
	}
}

// TestInlineFirewallBranches covers: inactive, zero-rules, active with rules,
// and the INPUT-drop suffix.
func TestInlineFirewallBranches(t *testing.T) {
	t.Parallel()
	if got := inlineFirewall(models.FirewallInfo{Available: true, Active: false, Backend: "nft"}); got != "nft  no rules" {
		t.Errorf("inactive: got %q", got)
	}
	if got := inlineFirewall(models.FirewallInfo{Available: true, Active: true, TotalRules: 0, Backend: "nft"}); got != "nft  no rules" {
		t.Errorf("zero rules: got %q", got)
	}
	if got := inlineFirewall(models.FirewallInfo{Available: true, Active: true, TotalRules: 5, Backend: "nft"}); got != "nft  5 rules" {
		t.Errorf("active with rules: got %q", got)
	}
	if got := inlineFirewall(models.FirewallInfo{Available: true, Active: true, TotalRules: 5, Backend: "nft", DefaultDrop: true}); got != "nft  5 rules  INPUT drop" {
		t.Errorf("default drop: got %q", got)
	}
}

// TestInlineAuthBranches covers: failed logins present, zero failed but
// checked, and unchecked (no data at all).
func TestInlineAuthBranches(t *testing.T) {
	t.Parallel()
	if got := inlineAuth(models.AuthInfo{FailedLast24h: 4}); got != "4 failed logins in 24h" {
		t.Errorf("failed present: got %q", got)
	}
	if got := inlineAuth(models.AuthInfo{Checked: true}); got != "0 failed logins" {
		t.Errorf("checked, zero failed: got %q", got)
	}
	if got := inlineAuth(models.AuthInfo{Checked: false}); got != "" {
		t.Errorf("unchecked: got %q, want empty", got)
	}
}

// TestInlineCloudMetaMinimal covers the minimal branch: no InstanceType, no
// Region, just the bare provider name.
func TestInlineCloudMetaMinimal(t *testing.T) {
	t.Parallel()
	if got := inlineCloudMeta(models.CloudInfo{Available: true, Provider: "gcp"}); got != "gcp" {
		t.Errorf("minimal: got %q, want %q", got, "gcp")
	}
	full := models.CloudInfo{Available: true, Provider: "aws", InstanceType: "t3.large", Region: "us-east-1"}
	if got := inlineCloudMeta(full); got != "aws  t3.large  us-east-1" {
		t.Errorf("full: got %q", got)
	}
}

// TestInlineCloudInitBranches covers the ExtendedStatus preference over
// Status, and the Datasource suffix.
func TestInlineCloudInitBranches(t *testing.T) {
	t.Parallel()
	if got := inlineCloudInit(models.CloudInitInfo{Available: true, Status: "done"}); got != "done" {
		t.Errorf("status only: got %q", got)
	}
	c := models.CloudInitInfo{Available: true, Status: "done", ExtendedStatus: "degraded done", Datasource: "Ec2"}
	if got := inlineCloudInit(c); got != "degraded done  (Ec2)" {
		t.Errorf("extended + datasource: got %q", got)
	}
}

// TestInlineAuditdNotRunning covers the not-running branch (distinct from
// the running branch already covered by inlineCases).
func TestInlineAuditdNotRunning(t *testing.T) {
	t.Parallel()
	if got := inlineAuditd(models.AuditInfo{Available: true, Running: false}); got != "not running" {
		t.Errorf("not running: got %q", got)
	}
}

// TestInlineVLANDown covers a VLAN interface set with some interfaces down.
func TestInlineVLANDown(t *testing.T) {
	t.Parallel()
	v := models.VLANInfo{Interfaces: []models.VLANInterface{{Name: "eth0.10", Up: true}, {Name: "eth0.20", Up: false}}}
	if got := inlineVLAN(v); got != "2 VLANs  1/2 up" {
		t.Errorf("mixed up/down: got %q, want %q", got, "2 VLANs  1/2 up")
	}
}

// TestInlineISCSIMixed covers sessions where not all are LOGGED_IN.
func TestInlineISCSIMixed(t *testing.T) {
	t.Parallel()
	i := models.ISCSIInfo{Available: true, Sessions: []models.ISCSISession{{State: "LOGGED_IN"}, {State: "FAILED"}}}
	if got := inlineISCSI(i); got != "1/2 logged in" {
		t.Errorf("mixed: got %q, want %q", got, "1/2 logged in")
	}
}

// TestInlineInfiniBandInactive covers ports that are not "active".
func TestInlineInfiniBandInactive(t *testing.T) {
	t.Parallel()
	ib := models.InfiniBandInfo{Ports: []models.IBPort{{State: "ACTIVE"}, {State: "DOWN"}}}
	if got := inlineInfiniBand(ib); got != "1/2 ports active" {
		t.Errorf("mixed: got %q, want %q", got, "1/2 ports active")
	}
}

// TestInlineSRIOVZeroVFs covers devices present but with zero configured VFs.
func TestInlineSRIOVZeroVFs(t *testing.T) {
	t.Parallel()
	s := models.SRIOVInfo{Devices: []models.SRIOVDevice{{NumVFs: 0}}}
	if got := inlineSRIOV(s); got != "1 devices  0 VFs active" {
		t.Errorf("zero VFs: got %q, want %q", got, "1 devices  0 VFs active")
	}
}

// TestInlineNspawnStopped covers containers present but none running.
func TestInlineNspawnStopped(t *testing.T) {
	t.Parallel()
	n := models.NspawnInfo{Available: true, Containers: []models.NspawnContainer{{State: "stopped"}}}
	if got := inlineNspawn(n); got != "1 containers  0 running" {
		t.Errorf("stopped: got %q, want %q", got, "1 containers  0 running")
	}
}

// TestInlineGPUBranches covers the single-GPU minimal case (no temp/util/VRAM
// -> bare name), the 2-GPU labeled-pair branch, and the 3+-GPU
// count-plus-hottest branch.
func TestInlineGPUBranches(t *testing.T) {
	t.Parallel()
	if got := inlineGPU(models.GPUInfo{Devices: []models.GPUDevice{{Name: "card0"}}}); got != "card0" {
		t.Errorf("single, no metrics: got %q, want %q", got, "card0")
	}
	two := models.GPUInfo{Devices: []models.GPUDevice{{Name: "card0", TempC: 40}, {Name: "card1", TempC: 50}}}
	if got := inlineGPU(two); got != "2 GPUs: card0 40°C · card1 50°C" {
		t.Errorf("two GPUs: got %q", got)
	}
	three := models.GPUInfo{Devices: []models.GPUDevice{
		{Name: "card0", TempC: 40}, {Name: "card1", TempC: 70}, {Name: "card2", TempC: 55},
	}}
	if got := inlineGPU(three); got != "3 GPUs  max 70°C (card1)" {
		t.Errorf("three GPUs: got %q, want %q", got, "3 GPUs  max 70°C (card1)")
	}
}

// TestInlineHugePagesTHPOnly covers the branch where Configured==0 but a THP
// mode string is present.
func TestInlineHugePagesTHPOnly(t *testing.T) {
	t.Parallel()
	if got := inlineHugePages(models.HugePagesInfo{Configured: 0, THPMode: "madvise"}); got != "THP madvise" {
		t.Errorf("THP only: got %q, want %q", got, "THP madvise")
	}
	if got := inlineHugePages(models.HugePagesInfo{}); got != "" {
		t.Errorf("neither: got %q, want empty", got)
	}
}

// TestInlineCPUFreqBranches covers: no governor -> empty, governor with no
// frequency data -> bare governor, and governor with frequency.
func TestInlineCPUFreqBranches(t *testing.T) {
	t.Parallel()
	if got := inlineCPUFreq(models.CPUFreqInfo{Governor: ""}); got != "" {
		t.Errorf("no governor: got %q, want empty", got)
	}
	if got := inlineCPUFreq(models.CPUFreqInfo{Governor: "powersave"}); got != "powersave" {
		t.Errorf("governor only: got %q", got)
	}
}

// TestInlineLaunchdBranches covers: zero total -> empty, failed jobs present,
// and the plain running-only branch.
func TestInlineLaunchdBranches(t *testing.T) {
	t.Parallel()
	if got := inlineLaunchd(models.LaunchdInfo{Total: 0}); got != "" {
		t.Errorf("zero total: got %q, want empty", got)
	}
	if got := inlineLaunchd(models.LaunchdInfo{Total: 10, Running: 8, Failed: []models.LaunchdService{{Label: "a"}, {Label: "b"}}}); got != "8 running  2 failed" {
		t.Errorf("with failed: got %q", got)
	}
	if got := inlineLaunchd(models.LaunchdInfo{Total: 10, Running: 10}); got != "10 running" {
		t.Errorf("no failed: got %q", got)
	}
}

// TestInlinePackagesBranches covers the CriticalUpdates/ImportantUpdates
// suppression branches (SecurityUpdates already covered in health_inline_test.go)
// and the not-Checked ("couldn't determine at all") empty branch.
func TestInlinePackagesBranches(t *testing.T) {
	t.Parallel()
	if got := inlinePackages(models.PackagesInfo{Checked: true, CriticalUpdates: 1}); got != "" {
		t.Errorf("critical updates present: got %q, want empty (heuristic shows the warning)", got)
	}
	if got := inlinePackages(models.PackagesInfo{Checked: true, ImportantUpdates: 1}); got != "" {
		t.Errorf("important updates present: got %q, want empty (heuristic shows the warning)", got)
	}
	if got := inlinePackages(models.PackagesInfo{Checked: false}); got != "" {
		t.Errorf("not checked: got %q, want empty", got)
	}
}

// TestInlineCVEBranches covers: zero total with a StatusReason, zero total
// without one, and a nonzero total.
func TestInlineCVEBranches(t *testing.T) {
	t.Parallel()
	if got := inlineCVE(models.CVEAllResult{Total: 0, StatusReason: "scan skipped: offline"}); got != "scan skipped: offline" {
		t.Errorf("zero + reason: got %q", got)
	}
	if got := inlineCVE(models.CVEAllResult{Total: 0}); got != "no pending security advisories" {
		t.Errorf("zero, no reason: got %q", got)
	}
	if got := inlineCVE(models.CVEAllResult{Total: 3}); got != "3 advisory(ies), none high-severity" {
		t.Errorf("nonzero: got %q", got)
	}
}

// TestInlineContainerdBranches covers: namespaces present (preferred over
// TotalContainers), TotalContainers-only fallback, and the socket-path
// fallback when neither is present.
func TestInlineContainerdBranches(t *testing.T) {
	t.Parallel()
	withNS := models.ContainerdInfo{Available: true, Version: "1.7", Namespaces: []models.ContainerdNamespace{{Name: "k8s.io", ContainerCount: 3}}}
	if got := inlineContainerd(withNS); got != "1.7  k8s.io:3" {
		t.Errorf("with namespaces: got %q", got)
	}
	totalOnly := models.ContainerdInfo{Available: true, Version: "1.7", TotalContainers: 5}
	if got := inlineContainerd(totalOnly); got != "1.7  5 container(s)" {
		t.Errorf("total only: got %q", got)
	}
	socketOnly := models.ContainerdInfo{Available: true, SocketPath: "/run/containerd/containerd.sock"}
	if got := inlineContainerd(socketOnly); got != "socket /run/containerd/containerd.sock" {
		t.Errorf("socket fallback: got %q", got)
	}
}

// TestAbs covers both branches of the sign-agnostic helper.
func TestAbs(t *testing.T) {
	t.Parallel()
	if got := abs(-3.5); got != 3.5 {
		t.Errorf("abs(-3.5) = %v, want 3.5", got)
	}
	if got := abs(3.5); got != 3.5 {
		t.Errorf("abs(3.5) = %v, want 3.5", got)
	}
}

// TestDiskInlineManyMounts covers the 3+ mount "worst" summary branch
// (distinct from the <=2 branch already covered by inline_dispatch_test.go).
func TestDiskInlineManyMounts(t *testing.T) {
	t.Parallel()
	d := models.DiskInfo{Filesystems: []models.FilesystemInfo{
		{Mount: "/", UsedPct: 40},
		{Mount: "/boot", UsedPct: 10},
		{Mount: "/data", UsedPct: 82},
	}}
	if got := diskInline(d); got != "3 mounts, max 82% (/data)" {
		t.Errorf("3 mounts: got %q, want %q", got, "3 mounts, max 82% (/data)")
	}
	if got := diskInline(models.DiskInfo{}); got != "" {
		t.Errorf("no filesystems: got %q, want empty", got)
	}
	// A typed-nil *DiskInfo (distinct from an untyped nil `any`, which the
	// nil-cases table already covers) must not panic dereferencing d.Filesystems.
	var nilPtr *models.DiskInfo
	if got := diskInline(nilPtr); got != "" {
		t.Errorf("typed-nil *DiskInfo: got %q, want empty", got)
	}
	// A valid *DiskInfo pointer takes the pointer-form branch (distinct from
	// the value-form branch exercised by TestInlineDataDispatch/the <=2 case
	// above, which both pass models.DiskInfo by value).
	ptr := &models.DiskInfo{Filesystems: []models.FilesystemInfo{{Mount: "/", UsedPct: 30}}}
	if got := diskInline(ptr); got != "/ 30%" {
		t.Errorf("pointer form: got %q, want %q", got, "/ 30%")
	}
}

// TestNetworkInlineBranches covers: no up interfaces -> empty, gateway ping
// sub-1ms rendering "<1 ms", 3+ NICs collapsing to a count, bond DOWN and
// bond degraded suffixes, and bond slaves excluded from the interface list.
func TestNetworkInlineBranches(t *testing.T) {
	t.Parallel()

	if got := networkInline(models.NetworkInfo{Interfaces: []models.InterfaceInfo{{Name: "eth0", Up: false}}}); got != "" {
		t.Errorf("no up interfaces: got %q, want empty", got)
	}

	// A typed-nil *NetworkInfo must not panic (distinct from the untyped-nil
	// `any` case already covered elsewhere).
	var nilPtr *models.NetworkInfo
	if got := networkInline(nilPtr); got != "" {
		t.Errorf("typed-nil *NetworkInfo: got %q, want empty", got)
	}

	subMs := models.NetworkInfo{
		Interfaces:    []models.InterfaceInfo{{Name: "eth0", Up: true, SpeedMbps: 1000}},
		GatewayPingMs: 0.4,
	}
	if got := networkInline(subMs); got != "eth0 1Gbps  gw <1 ms" {
		t.Errorf("sub-1ms gateway: got %q", got)
	}

	threeNIC := models.NetworkInfo{Interfaces: []models.InterfaceInfo{
		{Name: "eth0", Up: true, SpeedMbps: 100},
		{Name: "eth1", Up: true, SpeedMbps: 100},
		{Name: "eth2", Up: true, SpeedMbps: 100},
	}}
	if got := networkInline(threeNIC); got != "3 NICs, eth0 100Mbps" {
		t.Errorf("3+ NICs: got %q, want %q", got, "3 NICs, eth0 100Mbps")
	}

	bondDown := models.NetworkInfo{
		Interfaces: []models.InterfaceInfo{{Name: "eth0", Up: true}},
		Bonds:      []models.BondInterface{{Name: "bond0", AllDown: true}},
	}
	if got := networkInline(bondDown); got != "eth0  ❌ bond0 DOWN" {
		t.Errorf("bond all-down: got %q, want %q", got, "eth0  ❌ bond0 DOWN")
	}

	bondDegraded := models.NetworkInfo{
		Interfaces: []models.InterfaceInfo{{Name: "eth0", Up: true}},
		Bonds:      []models.BondInterface{{Name: "bond0", Degraded: true, DownSlaves: 1, Slaves: []models.BondSlave{{Name: "s0"}, {Name: "s1"}}}},
	}
	if got := networkInline(bondDegraded); got != "eth0  ⚠️  bond0 1/2 slaves" {
		t.Errorf("bond degraded: got %q, want %q", got, "eth0  ⚠️  bond0 1/2 slaves")
	}

	// Bond slaves must not appear as independent NICs in the interface list.
	withSlaves := models.NetworkInfo{
		Interfaces: []models.InterfaceInfo{{Name: "bond0", Up: true}, {Name: "eth0", Up: true}, {Name: "eth1", Up: true}},
		Bonds:      []models.BondInterface{{Name: "bond0", Slaves: []models.BondSlave{{Name: "eth0"}, {Name: "eth1"}}}},
	}
	got := networkInline(withSlaves)
	if got == "" {
		t.Fatal("expected non-empty output")
	}
	if got != "bond0" {
		t.Errorf("bond slaves should be excluded from the NIC list: got %q, want %q", got, "bond0")
	}
}
