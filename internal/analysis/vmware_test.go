package analysis

import (
	"strings"
	"testing"

	"github.com/keyorixhq/dashdiag/internal/models"
)

func TestCheckVMware(t *testing.T) {
	// Not a guest → completely silent (gate).
	if got := checkVMware(models.VMwareInfo{}); got != nil {
		t.Errorf("non-guest should yield no insights, got %v", got)
	}

	// Healthy guest → a single INFO recognition line, enriched with the
	// paravirtual-driver state (NIC drivers / pvscsi / balloon).
	healthy := models.VMwareInfo{
		IsGuest: true, ProductName: "VMware7,1",
		ToolsInstalled: true, ToolsRunning: true,
		StatAvailable: true, // stats read, no host pressure
		NICDrivers:    map[string]string{"ens160": "vmxnet3", "ens192": "vmxnet3"},
		PVSCSILoaded:  true,
		BalloonLoaded: false,
	}
	got := checkVMware(healthy)
	if len(got) != 1 || got[0].Level != "INFO" {
		t.Fatalf("healthy guest = %+v, want one INFO line", got)
	}
	for _, want := range []string{"VMware7,1", "vmxnet3", "paravirtual SCSI: yes", "balloon: no"} {
		if !strings.Contains(got[0].Message, want) {
			t.Errorf("INFO line missing %q, got %q", want, got[0].Message)
		}
	}

	// Tools not installed → WARN (and no INFO line).
	noTools := checkVMware(models.VMwareInfo{IsGuest: true, ToolsInstalled: false})
	if len(noTools) != 1 || noTools[0].Level != "WARN" ||
		!strings.Contains(noTools[0].Message, "not installed") {
		t.Errorf("missing tools = %+v, want WARN 'not installed'", noTools)
	}

	// Tools installed but stopped → WARN about not running.
	stopped := checkVMware(models.VMwareInfo{IsGuest: true, ToolsInstalled: true, ToolsRunning: false})
	if len(stopped) != 1 || stopped[0].Level != "WARN" ||
		!strings.Contains(stopped[0].Message, "not running") {
		t.Errorf("stopped tools = %+v, want WARN 'not running'", stopped)
	}

	// Emulated NIC → WARN naming the iface and driver.
	emulated := checkVMware(models.VMwareInfo{
		IsGuest: true, ToolsInstalled: true, ToolsRunning: true,
		StatAvailable: true,
		EmulatedNICs:  []string{"ens160"},
		NICDrivers:    map[string]string{"ens160": "e1000"},
	})
	if len(emulated) != 1 || emulated[0].Level != "WARN" {
		t.Fatalf("emulated NIC = %+v, want one WARN", emulated)
	}
	if !strings.Contains(emulated[0].Message, "ens160 (e1000)") {
		t.Errorf("emulated WARN should name 'ens160 (e1000)', got %q", emulated[0].Message)
	}

	// Both tools-stopped AND emulated NIC → two WARNs, no INFO.
	both := checkVMware(models.VMwareInfo{
		IsGuest: true, ToolsInstalled: true, ToolsRunning: false,
		EmulatedNICs: []string{"ens160"},
		NICDrivers:   map[string]string{"ens160": "e1000"},
	})
	if len(both) != 2 {
		t.Errorf("tools-stopped + emulated NIC = %d insights, want 2", len(both))
	}
	for _, ins := range both {
		if ins.Level != "WARN" {
			t.Errorf("expected all WARN, got %s", ins.Level)
		}
	}
}

// Host-imposed resource pressure (balloon/swap/limits) surfaces as WARN lines,
// and never fires unless the stat counters were actually readable.
func TestCheckVMwareResourceConstraints(t *testing.T) {
	base := func() models.VMwareInfo {
		return models.VMwareInfo{IsGuest: true, ToolsInstalled: true, ToolsRunning: true}
	}

	// StatAvailable=false → constraint fields ignored even if non-zero (stale/zero
	// values must never produce a phantom WARN).
	noStat := base()
	noStat.BalloonMB = 512
	noStat.CPULimitMHz = 1000
	if got := vmwareResourceConstraints(noStat); got != nil {
		t.Errorf("stat unavailable must yield no constraint insights, got %v", got)
	}

	// Stat available but everything clean → no insights (INFO line handled by caller).
	clean := base()
	clean.StatAvailable = true
	if got := vmwareResourceConstraints(clean); got != nil {
		t.Errorf("clean stat must yield no insights, got %v", got)
	}

	// All four constraints set → four WARNs naming the values.
	all := base()
	all.StatAvailable = true
	all.BalloonMB = 768
	all.HostSwapMB = 256
	all.MemLimitMB = 2048
	all.CPULimitMHz = 1500
	got := vmwareResourceConstraints(all)
	if len(got) != 4 {
		t.Fatalf("four constraints = %d insights, want 4", len(got))
	}
	for _, ins := range got {
		if ins.Level != "WARN" {
			t.Errorf("constraint insight should be WARN, got %s", ins.Level)
		}
	}
	joined := got[0].Message + got[1].Message + got[2].Message + got[3].Message
	for _, want := range []string{"768 MB", "256 MB", "2048 MB", "1500 MHz"} {
		if !strings.Contains(joined, want) {
			t.Errorf("constraint WARNs missing %q, got %q", want, joined)
		}
	}

	// A single constraint fires alone.
	balloonOnly := base()
	balloonOnly.StatAvailable = true
	balloonOnly.BalloonMB = 64
	if got := vmwareResourceConstraints(balloonOnly); len(got) != 1 ||
		!strings.Contains(got[0].Message, "balloon") {
		t.Errorf("balloon-only = %+v, want one balloon WARN", got)
	}
}

// §N (found live on a real VCD guest): a configured limit that sits AT/ABOVE the
// VM's capacity is inert — it can never throttle/balloon — so it must be INFO
// ("non-binding"), not a WARN claiming active harm. A limit BELOW capacity is a
// real WARN. When capacity is unknown the conservative WARN is kept. Values are
// the real measured ones: cpu_limit auto-scaled to 6000 == 2×2993 capacity;
// mem_limit 2048 sat above 1920 MB RAM.
func TestVMwareResourceConstraintsBinding(t *testing.T) {
	base := func() models.VMwareInfo {
		return models.VMwareInfo{IsGuest: true, ToolsInstalled: true, ToolsRunning: true, StatAvailable: true}
	}
	onlyLevel := func(t *testing.T, ins []models.Insight, want, mustContain string) {
		t.Helper()
		if len(ins) != 1 {
			t.Fatalf("want exactly one insight, got %d: %+v", len(ins), ins)
		}
		if ins[0].Level != want {
			t.Errorf("level=%s want %s (msg: %q)", ins[0].Level, want, ins[0].Message)
		}
		if !strings.Contains(ins[0].Message, mustContain) {
			t.Errorf("message %q missing %q", ins[0].Message, mustContain)
		}
	}

	// Non-binding memory limit (≥ RAM) → INFO, not WARN.
	memInert := base()
	memInert.MemLimitMB = 2048
	memInert.TotalRAMMB = 1920
	onlyLevel(t, vmwareResourceConstraints(memInert), "INFO", "non-binding")

	// Binding memory limit (< RAM) → WARN.
	memBind := base()
	memBind.MemLimitMB = 1000
	memBind.TotalRAMMB = 2048
	onlyLevel(t, vmwareResourceConstraints(memBind), "WARN", "1000 MB")

	// Non-binding CPU limit (== capacity, the real auto-scaled case) → INFO.
	cpuInert := base()
	cpuInert.CPULimitMHz = 6000
	cpuInert.NumVCPU = 2
	cpuInert.HostMHzPerCPU = 2993
	onlyLevel(t, vmwareResourceConstraints(cpuInert), "INFO", "non-binding")

	// Binding CPU limit (well below capacity) → WARN.
	cpuBind := base()
	cpuBind.CPULimitMHz = 1500
	cpuBind.NumVCPU = 2
	cpuBind.HostMHzPerCPU = 2993
	onlyLevel(t, vmwareResourceConstraints(cpuBind), "WARN", "1500 MHz")

	// Capacity unknown (no vCPU/host-clock context, e.g. `stat speed` unavailable):
	// keep the conservative WARN, but it must NOT assert throttling as fact — it can
	// only say the limit couldn't be sized. (Found live: lumping unknown-capacity in
	// with proven-binding false-WARNed "the guest is throttled regardless of host
	// load" on a VCD tenant whose limit actually sat at/above capacity.)
	unknown := base()
	unknown.CPULimitMHz = 6000
	uIns := vmwareResourceConstraints(unknown)
	onlyLevel(t, uIns, "WARN", "could not be determined")
	if strings.Contains(uIns[0].Message, "is throttled") {
		t.Errorf("unknown-capacity WARN must not assert throttling as fact: %q", uIns[0].Message)
	}
}

// An implausible `vmware-toolbox-cmd stat speed` (per-vCPU clock) must NOT be used
// to size CPU capacity — it would flip the headline pilot verdict. This guards the
// believer-moment false-positive: a garbage-HIGH clock inflates capacity so a
// non-binding limit reads "the guest is throttled" (invented), and a garbage-LOW
// clock shrinks capacity so a real throttle is hidden. Both must degrade to the
// honest "could not be determined" WARN, never assert throttling.
func TestVMwareCPULimitImplausibleSpeed(t *testing.T) {
	base := models.VMwareInfo{IsGuest: true, ToolsInstalled: true, ToolsRunning: true, StatAvailable: true}

	for _, speed := range []int{100, 99999, 0, 200000} {
		v := base
		v.CPULimitMHz = 6000 // a 6000 MHz limit on a 2-vCPU ~3GHz host is NON-binding
		v.NumVCPU = 2
		v.HostMHzPerCPU = speed
		ins := vmwareResourceConstraints(v)
		if len(ins) != 1 {
			t.Fatalf("speed=%d: want 1 insight, got %d", speed, len(ins))
		}
		if ins[0].Level != "WARN" || !strings.Contains(ins[0].Message, "could not be determined") {
			t.Errorf("speed=%d: implausible clock must give the unknown-capacity WARN, got %s: %q", speed, ins[0].Level, ins[0].Message)
		}
		if strings.Contains(ins[0].Message, "is throttled") || strings.Contains(ins[0].Message, "non-binding") {
			t.Errorf("speed=%d: implausible clock must not assert binding OR non-binding: %q", speed, ins[0].Message)
		}
	}

	// Sanity: a plausible clock still classifies normally (non-binding here).
	v := base
	v.CPULimitMHz = 6000
	v.NumVCPU = 2
	v.HostMHzPerCPU = 2993 // capacity 5986 ≈ 6000 → non-binding
	ins := vmwareResourceConstraints(v)
	if len(ins) != 1 || ins[0].Level != "INFO" {
		t.Errorf("plausible clock should classify (non-binding INFO here), got %+v", ins)
	}
}

// FALSE_OK_SWEEP #33: open-vm-tools running but the stat interface didn't answer →
// resource-pressure (ballooning/host-swap/caps) is unverified, NOT a clean OK.
func TestCheckVMwareStatUnavailable(t *testing.T) {
	// ToolsRunning + !StatAvailable → an explicit "not verified" INFO, and the
	// all-clean recognition line must NOT be the sole output.
	v := models.VMwareInfo{
		IsGuest: true, ProductName: "VMware7,1",
		ToolsInstalled: true, ToolsRunning: true, StatAvailable: false,
		NICDrivers: map[string]string{"ens160": "vmxnet3"}, PVSCSILoaded: true,
	}
	got := checkVMware(v)
	if !hasInsightMsg(got, "INFO", "resource-pressure stats unavailable") {
		t.Errorf("stat-unavailable must INFO 'not verified', got %+v", got)
	}
	// The misleading all-clean recognition line must not appear.
	for _, ins := range got {
		if strings.Contains(ins.Message, "open-vm-tools running; NICs") {
			t.Errorf("must not emit the all-clean recognition line when stats unverified, got %+v", ins)
		}
	}
	// Stats available + clean → the recognition line, no not-verified INFO.
	v.StatAvailable = true
	if got := checkVMware(v); hasInsightMsg(got, "INFO", "resource-pressure stats unavailable") {
		t.Errorf("verified stats must not say unavailable, got %+v", got)
	}
}

// SCSI command timeout below 180s surfaces as a WARN naming the disk and value.
func TestCheckVMwareSCSITimeout(t *testing.T) {
	// No low-timeout disks → silent.
	if got := vmwareSCSITimeoutCheck(models.VMwareInfo{IsGuest: true}); got != nil {
		t.Errorf("no low-timeout disks must be silent, got %v", got)
	}

	v := models.VMwareInfo{
		IsGuest:         true,
		SCSITimeouts:    map[string]int{"sda": 30, "sdb": 180},
		LowSCSITimeouts: []string{"sda"},
	}
	got := vmwareSCSITimeoutCheck(v)
	if len(got) != 1 || got[0].Level != "WARN" {
		t.Fatalf("low SCSI timeout = %+v, want one WARN", got)
	}
	if !strings.Contains(got[0].Message, "sda (30s)") {
		t.Errorf("SCSI WARN should name 'sda (30s)', got %q", got[0].Message)
	}
	if strings.Contains(got[0].Message, "sdb") {
		t.Errorf("compliant disk sdb must not appear, got %q", got[0].Message)
	}
}

// vmwareEnableUUIDCheck WARNs when SCSI disks lack a stable hardware ID (the
// disk.EnableUUID=FALSE signature), naming the affected disks; silent when no
// SCSI disks were examined or all carry an ID.
func TestCheckVMwareEnableUUID(t *testing.T) {
	// SCSI disks examined, some without a stable ID → WARN naming them.
	v := models.VMwareInfo{
		IsGuest:          true,
		SCSIDisksChecked: true,
		DisksNoStableID:  []string{"sdb", "sdd"},
	}
	got := vmwareEnableUUIDCheck(v)
	if len(got) != 1 || got[0].Level != "WARN" {
		t.Fatalf("disks without ID = %+v, want one WARN", got)
	}
	for _, want := range []string{"EnableUUID", "sdb", "sdd", "CSI"} {
		if !strings.Contains(got[0].Message, want) {
			t.Errorf("WARN missing %q, got %q", want, got[0].Message)
		}
	}

	// All SCSI disks carry an ID → silent (EnableUUID on).
	if got := vmwareEnableUUIDCheck(models.VMwareInfo{IsGuest: true, SCSIDisksChecked: true}); got != nil {
		t.Errorf("all disks with ID must be silent, got %v", got)
	}

	// No SCSI disks examined (NVMe-only) → silent even if the slice were non-empty.
	if got := vmwareEnableUUIDCheck(models.VMwareInfo{IsGuest: true, SCSIDisksChecked: false, DisksNoStableID: []string{"sdb"}}); got != nil {
		t.Errorf("unchecked SCSI must be silent, got %v", got)
	}
}

// vmwareVMXNETCheck WARNs when a vmxnet3 NIC's ring/buffer-exhaustion counters
// exceed the rate floor, and stays silent on a healthy NIC or a trivial flat
// count on a long-uptime host (rate-gated via nicErrorRateHigh).
func TestCheckVMwareVMXNET(t *testing.T) {
	// Healthy: zero counters → silent.
	healthy := models.VMwareInfo{IsGuest: true, VMXNETStats: []models.VMXNETStats{
		{Iface: "ens160", RxPackets: 1_000_000, TxPackets: 1_000_000},
	}}
	if got := vmwareVMXNETCheck(healthy); got != nil {
		t.Errorf("healthy vmxnet3 must be silent, got %v", got)
	}

	// Trivial count on heavy traffic → below the rate floor → silent (no false-WARN
	// on a long-uptime host).
	trivial := models.VMwareInfo{IsGuest: true, VMXNETStats: []models.VMXNETStats{
		{Iface: "ens160", RxBufAllocFail: 50, RxPackets: 1_000_000_000, TxPackets: 1_000_000_000},
	}}
	if got := vmwareVMXNETCheck(trivial); got != nil {
		t.Errorf("trivial count under the floor must be silent, got %v", got)
	}

	// Sustained exhaustion (well above floor and >0.01% of packets) → WARN naming
	// the iface and the reason.
	bad := models.VMwareInfo{IsGuest: true, VMXNETStats: []models.VMXNETStats{
		{Iface: "ens160", TxRingFull: 50_000, RxBufAllocFail: 40_000, RxPackets: 1_000_000, TxPackets: 1_000_000},
	}}
	got := vmwareVMXNETCheck(bad)
	if len(got) != 1 || got[0].Level != "WARN" {
		t.Fatalf("undersized rings = %+v, want one WARN", got)
	}
	for _, want := range []string{"ens160", "TX ring exhaustion", "buffer-allocation", "ethtool -G"} {
		if !strings.Contains(got[0].Message+got[0].Hints[1], want) {
			t.Errorf("WARN/hints missing %q, got %q / %v", want, got[0].Message, got[0].Hints)
		}
	}
}

// The constraint and timeout checks compose with the existing tools/NIC checks
// inside checkVMware (and suppress the all-clean INFO line when any WARN fires).
func TestCheckVMwareConstraintsIntegration(t *testing.T) {
	v := models.VMwareInfo{
		IsGuest: true, ProductName: "VMware7,1",
		ToolsInstalled: true, ToolsRunning: true,
		NICDrivers:      map[string]string{"ens160": "vmxnet3"},
		StatAvailable:   true,
		CPULimitMHz:     1200,
		SCSITimeouts:    map[string]int{"sda": 30},
		LowSCSITimeouts: []string{"sda"},
	}
	got := checkVMware(v)
	if len(got) != 2 {
		t.Fatalf("cpu-limit + low-timeout = %d insights, want 2 (no INFO line)", len(got))
	}
	for _, ins := range got {
		if ins.Level != "WARN" {
			t.Errorf("expected all WARN, got %s: %q", ins.Level, ins.Message)
		}
	}
}

// vmwareNICSummary lists distinct drivers (sorted, de-duplicated) for the
// recognition line, and reports "none detected" when no NICs were read.
func TestVMwareNICSummary(t *testing.T) {
	if got := vmwareNICSummary(models.VMwareInfo{}); got != "none detected" {
		t.Errorf("no NICs = %q, want 'none detected'", got)
	}
	mixed := models.VMwareInfo{NICDrivers: map[string]string{
		"ens160": "vmxnet3", "ens192": "vmxnet3", "ens224": "e1000",
	}}
	if got := vmwareNICSummary(mixed); got != "e1000, vmxnet3" {
		t.Errorf("mixed drivers = %q, want 'e1000, vmxnet3' (sorted, de-duped)", got)
	}
}

// emulatedNICDescs falls back to the bare iface name when the driver is unknown.
func TestEmulatedNICDescs(t *testing.T) {
	v := models.VMwareInfo{
		EmulatedNICs: []string{"ens160", "ens224"},
		NICDrivers:   map[string]string{"ens160": "e1000"}, // ens224 missing
	}
	got := emulatedNICDescs(v)
	if len(got) != 2 || got[0] != "ens160 (e1000)" || got[1] != "ens224" {
		t.Errorf("emulatedNICDescs = %v, want [ens160 (e1000), ens224]", got)
	}
}
