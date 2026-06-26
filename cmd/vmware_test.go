package cmd

import (
	"bytes"
	"strings"
	"testing"
	"time"

	"github.com/keyorixhq/dashdiag/internal/models"
	"github.com/keyorixhq/dashdiag/internal/output"
)

// tenantVMwareInfo mirrors the real VCD-tenant capture (ubuntumin): two emulated
// NICs, sda/sde SCSI timeout at the 30s default, three pvscsi disks with no stable
// ID (EnableUUID off), a CPU limit whose capacity can't be sized, and a memory
// limit that sits above RAM (non-binding). It's the demo-path fixture.
func tenantVMwareInfo() *models.VMwareInfo {
	return &models.VMwareInfo{
		IsGuest:          true,
		ProductName:      "VMware7,1",
		ToolsInstalled:   true,
		ToolsRunning:     true,
		NICDrivers:       map[string]string{"ens161": "e1000e", "ens33": "e1000"},
		EmulatedNICs:     []string{"ens161", "ens33"},
		StatAvailable:    true,
		MemLimitMB:       2048,
		TotalRAMMB:       1968, // limit ≥ RAM → non-binding INFO
		CPULimitMHz:      3000, // HostMHzPerCPU/NumVCPU unknown → "couldn't size it" WARN
		SCSITimeouts:     map[string]int{"sda": 30, "sde": 30},
		LowSCSITimeouts:  []string{"sda", "sde"},
		SCSIDisksChecked: true,
		DisksNoStableID:  []string{"sdb", "sdc", "sdd"},
	}
}

func TestPrintVMwareReport_TwoBlockSplit(t *testing.T) {
	var buf bytes.Buffer
	printVMwareReport(&buf, tenantVMwareInfo(), 100*time.Millisecond, output.ModePlain)
	out := buf.String()
	t.Logf("\n%s", out) // eyeball the demo output with -v

	guestHdr := "Your VM — you can fix these"
	hostHdr := "Host-side — evidence to share with your cloud provider"
	gi := strings.Index(out, guestHdr)
	hi := strings.Index(out, hostHdr)
	if gi < 0 || hi < 0 {
		t.Fatalf("both block headers must be present; got:\n%s", out)
	}
	if gi > hi {
		t.Errorf("guest block must come before host block (self-serve first)")
	}
	guestBlock, hostBlock := out[gi:hi], out[hi:]

	// Guest-fixable findings land in the guest block.
	for _, want := range []string{"emulated driver", "SCSI disk command timeout", "EnableUUID"} {
		if !strings.Contains(guestBlock, want) {
			t.Errorf("guest block missing %q", want)
		}
	}
	// Host-imposed findings land in the host block.
	for _, want := range []string{"CPU limit", "memory limit"} {
		if !strings.Contains(hostBlock, want) {
			t.Errorf("host block missing %q", want)
		}
	}
	// A guest-fixable finding must NOT appear under the host header (no leakage).
	if strings.Contains(hostBlock, "emulated driver") {
		t.Errorf("emulated-NIC (guest-fixable) leaked into the host block")
	}
	// The non-binding memory limit is INFO, not a counted concern.
	if c := vmwareConcerns(tenantVMwareInfo()); c != 4 {
		t.Errorf("vmwareConcerns = %d, want 4 (emulated NIC + CPU limit + SCSI + EnableUUID; mem limit is non-binding INFO)", c)
	}
	if !strings.Contains(out, "4 VMware config issue(s) found") {
		t.Errorf("summary line should report 4 issues; got:\n%s", out)
	}
}

func TestPrintVMwareReport_Healthy(t *testing.T) {
	// A clean paravirtual guest: vmxnet3 NIC, tools running, no limits/pressure.
	clean := &models.VMwareInfo{
		IsGuest: true, ProductName: "VMware20,1",
		ToolsInstalled: true, ToolsRunning: true, StatAvailable: true,
		NICDrivers: map[string]string{"ens192": "vmxnet3"}, PVSCSILoaded: true, BalloonLoaded: true,
	}
	var buf bytes.Buffer
	printVMwareReport(&buf, clean, 50*time.Millisecond, output.ModePlain)
	out := buf.String()
	if vmwareConcerns(clean) != 0 {
		t.Fatalf("clean guest should have 0 concerns, got %d", vmwareConcerns(clean))
	}
	if !strings.Contains(out, "VMware guest healthy") {
		t.Errorf("clean guest should print the healthy summary; got:\n%s", out)
	}
	// Both blocks still render their "nothing flagged" line so the operator sees
	// each side was actually checked.
	if strings.Count(out, "nothing flagged") != 2 {
		t.Errorf("expected both blocks to show 'nothing flagged'; got:\n%s", out)
	}
}
