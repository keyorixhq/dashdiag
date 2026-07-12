package render

import (
	"testing"

	"github.com/keyorixhq/dashdiag/internal/models"
)

// The inline* renderers take interface{} and type-assert to a concrete model.
// On a failed assertion they return "" with no error — so a refactor that breaks
// an assertion (or drops the value-vs-pointer branch) silently blanks a field in
// the health report. These tests guard that class of regression for a
// representative set of renderers:
//   - nil and wrong-type input must return "" (the defensive guard)
//   - valid input in BOTH value and pointer form must return non-empty

type inlineFn = func(any) string

type inlineCase struct {
	fn    inlineFn
	value any // valid input, value form
	ptr   any // same data, pointer form
}

func inlineCases() map[string]inlineCase {
	return map[string]inlineCase{
		"CPULoad":    {inlineCPULoad, models.CPUInfo{UsagePct: 50}, &models.CPUInfo{UsagePct: 50}},
		"Memory":     {inlineMemory, models.MemoryInfo{TotalGB: 16, UsedPct: 50}, &models.MemoryInfo{TotalGB: 16, UsedPct: 50}},
		"Swap":       {inlineSwap, models.SwapInfo{TotalGB: 4, UsedGB: 1}, &models.SwapInfo{TotalGB: 4, UsedGB: 1}},
		"Entropy":    {inlineEntropy, models.EntropyInfo{Available: true, EntropyBits: 256}, &models.EntropyInfo{Available: true, EntropyBits: 256}},
		"FDLimits":   {inlineFDLimits, models.FDInfo{MaxCount: 1000, OpenCount: 500, UsedPct: 50}, &models.FDInfo{MaxCount: 1000, OpenCount: 500, UsedPct: 50}},
		"OOM":        {inlineOOM, models.OOMInfo{Available: true, EventsLast24h: 3}, &models.OOMInfo{Available: true, EventsLast24h: 3}},
		"LVM":        {inlineLVM, models.LVMInfo{VGs: []models.LVMVG{{}}}, &models.LVMInfo{VGs: []models.LVMVG{{}}}},
		"Sessions":   {inlineSessions, models.SessionsInfo{TotalCount: 2}, &models.SessionsInfo{TotalCount: 2}},
		"IPMI":       {inlineIPMI, models.IPMIInfo{Available: true}, &models.IPMIInfo{Available: true}},
		"IO":         {inlineIO, models.IOInfo{Devices: []models.IODeviceInfo{{Name: "sda", AwaitMs: 2}}}, &models.IOInfo{Devices: []models.IODeviceInfo{{Name: "sda", AwaitMs: 2}}}},
		"KernelSec":  {inlineKernelSec, models.KernelSecurityInfo{SELinuxPresent: true, SELinuxMode: "enforcing"}, &models.KernelSecurityInfo{SELinuxPresent: true, SELinuxMode: "enforcing"}},
		"Clock":      {inlineClock, models.ClockInfo{Synced: true, OffsetMs: 1}, &models.ClockInfo{Synced: true, OffsetMs: 1}},
		"Logs":       {inlineLogs, models.LogsInfo{JournalSizeGB: 1}, &models.LogsInfo{JournalSizeGB: 1}},
		"CPUThermal": {inlineCPUThermal, models.ThermalInfo{CPUTempC: 50}, &models.ThermalInfo{CPUTempC: 50}},
		"Battery":    {inlineBattery, models.BatteryInfo{Present: true, CapacityPct: 80}, &models.BatteryInfo{Present: true, CapacityPct: 80}},
		"Drives":     {inlineDrives, models.NVMeInfo{Devices: []models.NVMeDevice{{Name: "nvme0", SmartRead: true, TempC: 30}}}, &models.NVMeInfo{Devices: []models.NVMeDevice{{Name: "nvme0", SmartRead: true, TempC: 30}}}},
		"Systemd":    {inlineSystemd, models.SystemdInfo{Available: true, TotalBootSec: 10}, &models.SystemdInfo{Available: true, TotalBootSec: 10}},
		"Processes":  {inlineProcesses, models.ProcessInfo{Total: 100}, &models.ProcessInfo{Total: 100}},
		"Bonding":    {inlineBonding, models.BondingInfo{Bonds: []models.BondInterface{{Name: "bond0", Slaves: []models.BondSlave{{Name: "eth0"}}}}}, &models.BondingInfo{Bonds: []models.BondInterface{{Name: "bond0", Slaves: []models.BondSlave{{Name: "eth0"}}}}}},
		"HBA":        {inlineHBA, models.HBAInfo{Ports: []models.HBAPort{{PortState: "Online"}}}, &models.HBAInfo{Ports: []models.HBAPort{{PortState: "Online"}}}},
		"Pressure":   {inlinePressure, models.PressureInfo{Available: true}, &models.PressureInfo{Available: true}},
		"Multipath":  {inlineMultipath, models.MultipathInfo{Available: true, Devices: []models.MultipathDevice{{Name: "mpatha", TotalPaths: 2}}}, &models.MultipathInfo{Available: true, Devices: []models.MultipathDevice{{Name: "mpatha", TotalPaths: 2}}}},
		"Ceph":       {inlineCeph, models.CephInfo{Available: true, Health: "HEALTH_OK"}, &models.CephInfo{Available: true, Health: "HEALTH_OK"}},
		"Firewall":   {inlineFirewall, models.FirewallInfo{Available: true, Active: true, TotalRules: 5, Backend: "nft"}, &models.FirewallInfo{Available: true, Active: true, TotalRules: 5, Backend: "nft"}},
		"Auth":       {inlineAuth, models.AuthInfo{Checked: true}, &models.AuthInfo{Checked: true}},
		"CloudMeta":  {inlineCloudMeta, models.CloudInfo{Available: true, Provider: "aws"}, &models.CloudInfo{Available: true, Provider: "aws"}},
		"CloudInit":  {inlineCloudInit, models.CloudInitInfo{Available: true, Status: "done"}, &models.CloudInitInfo{Available: true, Status: "done"}},
		"Auditd":     {inlineAuditd, models.AuditInfo{Available: true, Running: true, RulesLoaded: 3}, &models.AuditInfo{Available: true, Running: true, RulesLoaded: 3}},
		"NUMA":       {inlineNUMA, models.NUMAInfo{Available: true, NodeCount: 2}, &models.NUMAInfo{Available: true, NodeCount: 2}},
		"VLAN":       {inlineVLAN, models.VLANInfo{Interfaces: []models.VLANInterface{{Name: "eth0.10", Up: true}}}, &models.VLANInfo{Interfaces: []models.VLANInterface{{Name: "eth0.10", Up: true}}}},
		"ISCSI":      {inlineISCSI, models.ISCSIInfo{Available: true, Sessions: []models.ISCSISession{{State: "LOGGED_IN"}}}, &models.ISCSIInfo{Available: true, Sessions: []models.ISCSISession{{State: "LOGGED_IN"}}}},
		"InfiniBand": {inlineInfiniBand, models.InfiniBandInfo{Ports: []models.IBPort{{State: "ACTIVE"}}}, &models.InfiniBandInfo{Ports: []models.IBPort{{State: "ACTIVE"}}}},
		"SRIOV":      {inlineSRIOV, models.SRIOVInfo{Devices: []models.SRIOVDevice{{NumVFs: 2}}}, &models.SRIOVInfo{Devices: []models.SRIOVDevice{{NumVFs: 2}}}},
		"Nspawn":     {inlineNspawn, models.NspawnInfo{Available: true, Containers: []models.NspawnContainer{{State: "running"}}}, &models.NspawnInfo{Available: true, Containers: []models.NspawnContainer{{State: "running"}}}},
		"GPU":        {inlineGPU, models.GPUInfo{Devices: []models.GPUDevice{{Name: "card0", TempC: 45}}}, &models.GPUInfo{Devices: []models.GPUDevice{{Name: "card0", TempC: 45}}}},
		"HugePages":  {inlineHugePages, models.HugePagesInfo{Configured: 100, Used: 50}, &models.HugePagesInfo{Configured: 100, Used: 50}},
		"CPUFreq":    {inlineCPUFreq, models.CPUFreqInfo{Governor: "performance", CurrentMHz: 3000, MaxMHz: 3000}, &models.CPUFreqInfo{Governor: "performance", CurrentMHz: 3000, MaxMHz: 3000}},
		"Launchd":    {inlineLaunchd, models.LaunchdInfo{Total: 10, Running: 10}, &models.LaunchdInfo{Total: 10, Running: 10}},
		"Packages":   {inlinePackages, models.PackagesInfo{Checked: true}, &models.PackagesInfo{Checked: true}},
		"CVE":        {inlineCVE, models.CVEAllResult{Total: 0}, &models.CVEAllResult{Total: 0}},
		"Containerd": {inlineContainerd, models.ContainerdInfo{Available: true, Version: "1.7"}, &models.ContainerdInfo{Available: true, Version: "1.7"}},
	}
}

func TestInlineNilAndWrongTypeReturnEmpty(t *testing.T) {
	type wrong struct{ X int }
	for name, c := range inlineCases() {
		if got := c.fn(nil); got != "" {
			t.Errorf("%s(nil) = %q, want empty", name, got)
		}
		if got := c.fn(wrong{1}); got != "" {
			t.Errorf("%s(wrong-type) = %q, want empty (silent type-assertion guard)", name, got)
		}
	}
}

func TestInlineValidInputNonEmpty(t *testing.T) {
	for name, c := range inlineCases() {
		if got := c.fn(c.value); got == "" {
			t.Errorf("%s(value form) returned empty for valid input", name)
		}
		if got := c.fn(c.ptr); got == "" {
			t.Errorf("%s(pointer form) returned empty for valid input", name)
		}
	}
}

// inlineMemory does arithmetic on the populated struct — pin its exact output as
// a representative formatting regression guard.
func TestInlineMemoryFormat(t *testing.T) {
	got := inlineMemory(models.MemoryInfo{TotalGB: 16, UsedPct: 50})
	if got != "8.0/16 GB (50%)" {
		t.Errorf("inlineMemory = %q, want %q", got, "8.0/16 GB (50%)")
	}
}

// A "0 updates" result must NOT render "up to date" when the update metadata is
// stale/absent — that's a false-OK. The heuristic surfaces the "cannot confirm"
// reason instead; the inline text must yield to it.
func TestInlinePackagesStaleNotUpToDate(t *testing.T) {
	stale := models.PackagesInfo{Checked: true, SecurityUpdates: 0, Status: "stale-metadata", PackageManager: "apt"}
	if got := inlinePackages(stale); got == "up to date" {
		t.Errorf("stale metadata: inlinePackages = %q, must not claim 'up to date'", got)
	}
	fresh := models.PackagesInfo{Checked: true, SecurityUpdates: 0, PackageManager: "apt"}
	if got := inlinePackages(fresh); got != "up to date" {
		t.Errorf("fresh/clean: inlinePackages = %q, want 'up to date'", got)
	}
}

// BUG-098: query-failed (scan timed out / errored) and no-security-repo must not
// render "up to date" either — Checked is set true at collector init before the
// scan even runs, so these two statuses previously fell through the same
// blacklist gap stale-metadata was fixed for above, reading as a false "up to
// date" summary on a scan that timed out (found on Oracle Linux, cold dnf cache).
func TestInlinePackagesQueryFailedNotUpToDate(t *testing.T) {
	cases := []models.PackagesInfo{
		{Checked: true, SecurityUpdates: 0, Status: "query-failed", PackageManager: "dnf"},
		{Checked: true, SecurityUpdates: 0, Status: "no-security-repo", PackageManager: "dnf"},
	}
	for _, p := range cases {
		if got := inlinePackages(p); got == "up to date" {
			t.Errorf("status %q: inlinePackages = %q, must not claim 'up to date'", p.Status, got)
		}
	}
}

// A drive detected via sysfs but with no SMART log read (no nvme-cli, common on
// minimal cloud/ARM images) must NOT be rendered "healthy" — that's a false-OK.
func TestInlineDrivesSmartUnread(t *testing.T) {
	// n non-nil (type-asserted OK) but no devices at all -> empty, not a panic
	// or a false "0 drives" line.
	if got := inlineDrives(models.NVMeInfo{}); got != "" {
		t.Errorf("no devices at all: inlineDrives = %q, want empty", got)
	}

	unread := models.NVMeInfo{Devices: []models.NVMeDevice{{Name: "/dev/nvme0", SmartRead: false}}}
	if got := inlineDrives(unread); got != "/dev/nvme0  detected (SMART not read)" {
		t.Errorf("unread drive: inlineDrives = %q, want SMART-not-read text", got)
	}
	read := models.NVMeInfo{Devices: []models.NVMeDevice{{Name: "/dev/nvme0", SmartRead: true}}}
	if got := inlineDrives(read); got != "/dev/nvme0  healthy" {
		t.Errorf("verified drive: inlineDrives = %q, want healthy", got)
	}
	mixed := models.NVMeInfo{Devices: []models.NVMeDevice{
		{Name: "/dev/nvme0", SmartRead: true}, {Name: "/dev/nvme1", SmartRead: false},
	}}
	if got := inlineDrives(mixed); got != "2 drives, 1 SMART not read" {
		t.Errorf("mixed drives: inlineDrives = %q, want count with unread note", got)
	}

	// SATA drives whose smartctl errored (non-root — validated on pve01) must NOT
	// be tallied as "healthy"; counting only NVMe here was the false-OK.
	sataErrored := models.NVMeInfo{SATADevices: []models.SATADevice{
		{Name: "/dev/sda", SmartRead: false, Error: "smartctl failed"},
		{Name: "/dev/sdb", SmartRead: false, Error: "smartctl failed"},
	}}
	if got := inlineDrives(sataErrored); got != "2 drives, 2 SMART not read" {
		t.Errorf("non-root SATA: inlineDrives = %q, want all-unread, not healthy", got)
	}
	singleSATAErr := models.NVMeInfo{SATADevices: []models.SATADevice{
		{Name: "/dev/sda", SmartRead: false, Error: "smartctl failed"},
	}}
	if got := inlineDrives(singleSATAErr); got != "/dev/sda  detected (SMART not read)" {
		t.Errorf("single errored SATA: inlineDrives = %q, want SMART-not-read text", got)
	}
	// A genuinely verified SATA drive still renders healthy.
	sataOK := models.NVMeInfo{SATADevices: []models.SATADevice{
		{Name: "/dev/sda", SmartRead: true, SmartOK: true},
	}}
	if got := inlineDrives(sataOK); got != "/dev/sda  healthy" {
		t.Errorf("verified SATA: inlineDrives = %q, want healthy", got)
	}

	// AWS EBS / virtual NVMe: SMART "read" but all sentinels (0K temp, all-zero) —
	// must NOT render "healthy" (validated live on a Graviton2 t4g.small).
	ebs := models.NVMeInfo{Devices: []models.NVMeDevice{
		{Name: "/dev/nvme0", SmartRead: true, TempC: -273},
		{Name: "/dev/nvme1", SmartRead: true, TempC: -273},
	}}
	if got := inlineDrives(ebs); got != "2 drives, 2 SMART not read" {
		t.Errorf("EBS sentinel NVMe: inlineDrives = %q, want all-unread, not healthy", got)
	}
	// A real NVMe with a real temp still renders healthy.
	realNVMe := models.NVMeInfo{Devices: []models.NVMeDevice{
		{Name: "/dev/nvme0", SmartRead: true, TempC: 35},
	}}
	if got := inlineDrives(realNVMe); got != "/dev/nvme0  healthy" {
		t.Errorf("real NVMe: inlineDrives = %q, want healthy", got)
	}

	// 2+ drives, all verified — the plain "N drives healthy" summary (distinct
	// from both the single-drive and the some-unread branches above).
	allHealthy := models.NVMeInfo{Devices: []models.NVMeDevice{
		{Name: "/dev/nvme0", SmartRead: true, TempC: 35},
		{Name: "/dev/nvme1", SmartRead: true, TempC: 40},
	}}
	if got := inlineDrives(allHealthy); got != "2 drives  healthy" {
		t.Errorf("all healthy multi-drive: inlineDrives = %q, want %q", got, "2 drives  healthy")
	}
}

// Sub-GB totals (small containers / minimal VMs) used to floor to "0 GB" under
// %.0f, rendering a broken-looking "0.1/0 GB". Below 1 GB we switch to MB.
func TestInlineMemorySubGB(t *testing.T) {
	got := inlineMemory(models.MemoryInfo{TotalGB: 0.5, UsedPct: 12})
	if got != "61/512 MB (12%)" {
		t.Errorf("inlineMemory = %q, want %q", got, "61/512 MB (12%)")
	}
}

// TestCPUDisplayPct covers the observer-effect reconciliation: the grid prefers
// the instantaneous user+sys% (htop match) but falls back to the load-derived
// figure when a light box reads implausibly high (dsd's own collection noise).
func TestCPUDisplayPct(t *testing.T) {
	cases := []struct {
		name        string
		usage, load float64
		want        float64
	}{
		{"idle box, contaminated reading → show load", 70, 0, 0},
		{"truly idle, mild contamination → show load", 35, 0, 0},
		{"normal light box, usage≈load → htop match", 25, 25, 25},
		{"boundary gap (==25) stays htop match", 40, 15, 40},
		{"busy box → instantaneous (htop match)", 81, 80, 81},
		{"I/O-bound: high load, low CPU → show low usage", 10, 90, 10},
		{"usage unavailable → fall back to load", 0, 12, 12},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := cpuDisplayPct(&models.CPUInfo{UsagePct: tc.usage, LoadPct: tc.load})
			if got != tc.want {
				t.Errorf("cpuDisplayPct(usage=%v, load=%v) = %v, want %v", tc.usage, tc.load, got, tc.want)
			}
		})
	}
}
