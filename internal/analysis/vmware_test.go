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
