package cmd

import (
	"strings"
	"testing"

	"github.com/keyorixhq/dashdiag/internal/models"
	"github.com/keyorixhq/dashdiag/internal/output"
)

// Golden-output tests for kvm.go's report renderers — plain data structs, no
// live I/O, so captureStdout exercises them directly. No t.Parallel() (it
// corrupts captureStdout's shared os.Stdout swap — see the pve.go/disk.go
// equivalents of this file).

func TestPrintKVMReportNotDetected(t *testing.T) {
	out := captureStdout(t, func() { printKVMReport(&models.KVMInfo{Detected: false}, 0, output.ModePlain) })
	if !strings.Contains(out, "libvirt not found") {
		t.Errorf("undetected libvirt should say so, got:\n%s", out)
	}
	if strings.Contains(out, "KVM healthy") {
		t.Errorf("undetected libvirt must not read healthy, got:\n%s", out)
	}
}

func TestPrintKVMVMsNone(t *testing.T) {
	out := captureStdout(t, func() { printKVMVMs(&models.KVMInfo{}, output.ModePlain) })
	if !strings.Contains(out, "none defined") {
		t.Errorf("no VMs should say none defined, got:\n%s", out)
	}
}

func TestPrintKVMVMsFindings(t *testing.T) {
	cases := []struct {
		name string
		vm   models.KVMVM
		want string
	}{
		{"disk io error", models.KVMVM{Name: "vm1", State: models.KVMRunning, DiskIOError: true}, "disk I/O error recorded"},
		{"missing disk", models.KVMVM{Name: "vm1", State: models.KVMShutOff, MissingDiskPath: "/var/lib/libvirt/images/vm1.qcow2"}, "disk image missing"},
		{"emulated nic", models.KVMVM{Name: "vm1", State: models.KVMRunning, EmulatedNICs: []string{"52:54:00:aa (rtl8139)"}}, "emulated driver"},
		{"emulated disk", models.KVMVM{Name: "vm1", State: models.KVMRunning, EmulatedDisks: []string{"vda (ide)"}}, "emulated bus"},
		{"shut off with autostart", models.KVMVM{Name: "vm1", State: models.KVMShutOff, AutoStart: true}, "autostart=yes"},
		{"max mem shown", models.KVMVM{Name: "vm1", State: models.KVMRunning, MaxMemMB: 4096}, "4096MB RAM"},
		{"last log error shown", models.KVMVM{Name: "vm1", State: models.KVMCrashed, LastLogError: "qemu: terminating on signal 15"}, "last log error: qemu: terminating on signal 15"},
	}
	for _, c := range cases {
		info := &models.KVMInfo{VMs: []models.KVMVM{c.vm}}
		out := captureStdout(t, func() { printKVMVMs(info, output.ModePlain) })
		if !strings.Contains(out, c.want) {
			t.Errorf("%s: printKVMVMs output missing %q, got:\n%s", c.name, c.want, out)
		}
	}
}

func TestPrintKVMNetworks(t *testing.T) {
	if out := captureStdout(t, func() { printKVMNetworks(&models.KVMInfo{}, output.ModePlain) }); out != "" {
		t.Errorf("no networks should print nothing, got:\n%s", out)
	}

	inactive := captureStdout(t, func() {
		printKVMNetworks(&models.KVMInfo{Networks: []models.KVMNetwork{{Name: "default", State: "inactive"}}}, output.ModePlain)
	})
	if !strings.Contains(inactive, "inactive") {
		t.Errorf("an inactive network should say so, got:\n%s", inactive)
	}

	// An active network whose bridge link is down must still be flagged even
	// though the network itself is "active" — the bridge icon must show WARN.
	bridgeDown := captureStdout(t, func() {
		printKVMNetworks(&models.KVMInfo{Networks: []models.KVMNetwork{
			{Name: "default", State: "active", Bridge: "virbr0", BridgeUp: false},
		}}, output.ModePlain)
	})
	if !strings.Contains(bridgeDown, "WARN") {
		t.Errorf("an active network with its bridge link down must render a WARN icon, got:\n%s", bridgeDown)
	}
}

func TestPrintKVMPools(t *testing.T) {
	if out := captureStdout(t, func() { printKVMPools(&models.KVMInfo{}, output.ModePlain) }); out != "" {
		t.Errorf("no pools should print nothing, got:\n%s", out)
	}

	inactive := captureStdout(t, func() {
		printKVMPools(&models.KVMInfo{StoragePools: []models.KVMStoragePool{{Name: "default", State: "inactive"}}}, output.ModePlain)
	})
	if !strings.Contains(inactive, "inactive") {
		t.Errorf("an inactive pool should say so, got:\n%s", inactive)
	}

	nearFull := captureStdout(t, func() {
		printKVMPools(&models.KVMInfo{StoragePools: []models.KVMStoragePool{
			{Name: "default", State: "active", CapacityGB: 100, AvailableGB: 10, UsedPct: 90},
		}}, output.ModePlain)
	})
	if !strings.Contains(nearFull, "WARN") {
		t.Errorf("a pool at 90%% used should render WARN, got:\n%s", nearFull)
	}

	almostFull := captureStdout(t, func() {
		printKVMPools(&models.KVMInfo{StoragePools: []models.KVMStoragePool{
			{Name: "default", State: "active", CapacityGB: 100, AvailableGB: 2, UsedPct: 98},
		}}, output.ModePlain)
	})
	if !strings.Contains(almostFull, "CRIT") {
		t.Errorf("a pool at 98%% used should render CRIT, got:\n%s", almostFull)
	}
}

// TestPrintKVMReportSummary pins the top-level healthy/concern tally, and that
// deep-only per-VM XML findings (missing backing file, emulated NIC/disk) each
// count toward it — the exact bug class kvmConcerns's own doc comment guards
// against drifting from checkKVM.
func TestPrintKVMReportSummary(t *testing.T) {
	healthy := captureStdout(t, func() {
		printKVMReport(&models.KVMInfo{Detected: true}, 0, output.ModePlain)
	})
	if !strings.Contains(healthy, "KVM healthy") {
		t.Errorf("no VMs/concerns should read healthy, got:\n%s", healthy)
	}

	concern := captureStdout(t, func() {
		printKVMReport(&models.KVMInfo{
			Detected: true,
			VMs:      []models.KVMVM{{Name: "vm1", State: models.KVMRunning, EmulatedDisks: []string{"vda (ide)"}}},
		}, 0, output.ModePlain)
	})
	if !strings.Contains(concern, "concern(s) found") {
		t.Errorf("an emulated-disk finding should surface as a concern, got:\n%s", concern)
	}
}

// A non-empty LibvirtVer/QEMUVer prints the version suffix on the identity line.
func TestPrintKVMReportVersionString(t *testing.T) {
	out := captureStdout(t, func() {
		printKVMReport(&models.KVMInfo{Detected: true, LibvirtVer: "9.0.0", QEMUVer: "7.2.0"}, 0, output.ModePlain)
	})
	if !strings.Contains(out, "[libvirt 9.0.0 / QEMU 7.2.0]") {
		t.Errorf("libvirt/QEMU versions should be shown, got:\n%s", out)
	}
}
