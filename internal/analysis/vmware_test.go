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
		EmulatedNICs: []string{"ens160"},
		NICDrivers:   map[string]string{"ens160": "e1000"},
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
