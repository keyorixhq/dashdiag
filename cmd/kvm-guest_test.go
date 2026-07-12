package cmd

import (
	"bytes"
	"strings"
	"testing"
	"time"

	"github.com/keyorixhq/dashdiag/internal/models"
	"github.com/keyorixhq/dashdiag/internal/output"
)

// A misconfigured Proxmox guest: emulated NIC + emulated disk (guest-fixable), the
// host not having enabled the guest-agent channel, and high CPU steal (both host-side).
func misconfiguredKVMGuest() *models.KVMGuestInfo {
	return &models.KVMGuestInfo{
		IsGuest:           true,
		ProductName:       "Standard PC (i440FX + PIIX, 1996)",
		QGAChannelPresent: false, // host-side: channel not enabled
		NICDrivers:        map[string]string{"eth0": "e1000"},
		EmulatedNICs:      []string{"eth0"},
		DiskBuses:         map[string]string{"sda": "sata"},
		EmulatedDisks:     []string{"sda"},
		Clocksource:       "kvm-clock",
		StealPct:          18, // host-side: overcommitted
	}
}

func TestPrintKVMGuestReport_TwoBlockSplit(t *testing.T) {
	var buf bytes.Buffer
	printKVMGuestReport(&buf, misconfiguredKVMGuest(), 100*time.Millisecond, output.ModePlain)
	out := buf.String()
	t.Logf("\n%s", out)

	guestHdr := "Your VM — you can fix these"
	hostHdr := "Host-side — evidence for whoever runs your hypervisor"
	gi := strings.Index(out, guestHdr)
	hi := strings.Index(out, hostHdr)
	if gi < 0 || hi < 0 || gi > hi {
		t.Fatalf("both blocks must be present, guest before host:\n%s", out)
	}
	guestBlock, hostBlock := out[gi:hi], out[hi:]

	// Guest-fixable: emulated NIC + emulated disk.
	for _, want := range []string{"emulated driver", "emulated bus"} {
		if !strings.Contains(guestBlock, want) {
			t.Errorf("guest block missing %q", want)
		}
	}
	// Host-side: CPU steal + the host not having enabled the agent channel.
	for _, want := range []string{"CPU steal", "has not enabled"} {
		if !strings.Contains(hostBlock, want) {
			t.Errorf("host block missing %q", want)
		}
	}
	// No leakage: steal must not appear under the guest header.
	if strings.Contains(guestBlock, "CPU steal") {
		t.Errorf("host-side CPU steal leaked into the guest block")
	}
	// Concerns counts WARN/CRIT only: emulated NIC + emulated disk + steal = 3
	// (the channel-absent line is INFO).
	if c := kvmGuestConcerns(misconfiguredKVMGuest()); c != 3 {
		t.Errorf("kvmGuestConcerns = %d, want 3 (NIC + disk + steal WARNs; channel-absent is INFO)", c)
	}
}

// TestRunKVMGuest_NotAvailable exercises runKVMGuest's real availability gate
// (this test host's DMI vendor is not QEMU) in both --plain and --json mode.
// No t.Parallel() — captureStdout swaps the shared os.Stdout.
func TestRunKVMGuest_NotAvailable(t *testing.T) {
	plainCmd := newBareCloudCmd()
	_ = plainCmd.Flags().Set("plain", "true")
	plainOut := captureStdout(t, func() {
		if err := runKVMGuest(plainCmd, nil); err != nil {
			t.Fatalf("runKVMGuest (plain): %v", err)
		}
	})
	if !strings.Contains(plainOut, "not running under QEMU/KVM") {
		t.Errorf("plain mode should report 'not running under QEMU/KVM', got: %q", plainOut)
	}

	jsonCmd := newBareCloudCmd()
	_ = jsonCmd.Flags().Set("json", "true")
	jsonOut := captureStdout(t, func() {
		if err := runKVMGuest(jsonCmd, nil); err != nil {
			t.Fatalf("runKVMGuest (json): %v", err)
		}
	})
	if !strings.Contains(jsonOut, `"is_guest"`) {
		t.Errorf("json mode should encode an empty KVMGuestInfo, got: %q", jsonOut)
	}
}

// An empty ProductName falls back to "QEMU/KVM", and a channel that is
// present but whose agent isn't running renders "channel present, agent NOT
// running" rather than "running" or the default "no agent channel".
func TestPrintKVMGuestReport_NameFallbackAndChannelNotRunning(t *testing.T) {
	var buf bytes.Buffer
	printKVMGuestReport(&buf, &models.KVMGuestInfo{
		IsGuest: true, QGAChannelPresent: true, QGAInstalled: false, QGARunning: false,
	}, 10*time.Millisecond, output.ModePlain)
	out := buf.String()
	if !strings.Contains(out, "QEMU/KVM guest — QEMU/KVM") {
		t.Errorf("empty product name should fall back to 'QEMU/KVM', got:\n%s", out)
	}
	if !strings.Contains(out, "qemu-guest-agent: channel present, agent NOT running") {
		t.Errorf("a present channel with the agent not running should say so, got:\n%s", out)
	}
}

func TestPrintKVMGuestReport_Healthy(t *testing.T) {
	clean := &models.KVMGuestInfo{
		IsGuest: true, ProductName: "Standard PC (Q35 + ICH9, 2009)",
		QGAChannelPresent: true, QGAInstalled: true, QGARunning: true,
		NICDrivers:  map[string]string{"eth0": "virtio_net"},
		DiskBuses:   map[string]string{"sda": "virtio-scsi"},
		Clocksource: "kvm-clock", BalloonLoaded: true,
	}
	var buf bytes.Buffer
	printKVMGuestReport(&buf, clean, 50*time.Millisecond, output.ModePlain)
	out := buf.String()
	if kvmGuestConcerns(clean) != 0 {
		t.Fatalf("clean guest should have 0 concerns, got %d", kvmGuestConcerns(clean))
	}
	if !strings.Contains(out, "KVM guest healthy") {
		t.Errorf("clean guest should print the healthy summary:\n%s", out)
	}
	if strings.Count(out, "nothing flagged") != 2 {
		t.Errorf("both blocks should show 'nothing flagged':\n%s", out)
	}
}
