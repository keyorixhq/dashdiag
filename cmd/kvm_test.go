package cmd

import (
	"strings"
	"testing"

	"github.com/keyorixhq/dashdiag/internal/models"
	"github.com/keyorixhq/dashdiag/internal/output"
)

// TestRunKVM exercises runKVM's real collector wiring (this test host has no
// libvirt, so it always lands on printKVMReport's "not detected" branch) in
// both --plain and --json mode, and with --deep set (a different collector
// construction path). No t.Parallel() — captureStdout swaps the shared
// os.Stdout.
func TestRunKVM(t *testing.T) {
	plainCmd := newBareCloudCmd()
	_ = plainCmd.Flags().Set("plain", "true")
	plainOut := captureStdout(t, func() {
		if err := runKVM(plainCmd, nil); err != nil {
			t.Fatalf("runKVM (plain): %v", err)
		}
	})
	if !strings.Contains(plainOut, "libvirt not found") {
		t.Errorf("no libvirt on this host should say so, got: %q", plainOut)
	}

	jsonCmd := newBareCloudCmd()
	_ = jsonCmd.Flags().Set("json", "true")
	jsonOut := captureStdout(t, func() {
		if err := runKVM(jsonCmd, nil); err != nil {
			t.Fatalf("runKVM (json): %v", err)
		}
	})
	if !strings.Contains(jsonOut, `"detected"`) {
		t.Errorf("json mode should encode a KVMInfo, got: %q", jsonOut)
	}

	deepCmd := newBareCloudCmd()
	_ = deepCmd.Flags().Set("plain", "true")
	_ = deepCmd.Flags().Set("deep", "true")
	deepOut := captureStdout(t, func() {
		if err := runKVM(deepCmd, nil); err != nil {
			t.Fatalf("runKVM (deep): %v", err)
		}
	})
	if !strings.Contains(deepOut, "libvirt not found") {
		t.Errorf("--deep with no libvirt should also say not found, got: %q", deepOut)
	}
}

func TestKVMVMIcon(t *testing.T) {
	cases := []struct {
		name string
		vm   models.KVMVM
		want string
	}{
		{"crashed", models.KVMVM{State: models.KVMCrashed}, "CRIT"},
		{"paused", models.KVMVM{State: models.KVMPaused}, "WARN"},
		{"running", models.KVMVM{State: models.KVMRunning}, "OK"},
		// A shut-off VM is normal (OFF) UNLESS it's supposed to autostart —
		// then it staying down is itself a fault worth flagging.
		{"shut off, no autostart", models.KVMVM{State: models.KVMShutOff}, "OFF"},
		{"shut off, autostart expected", models.KVMVM{State: models.KVMShutOff, AutoStart: true}, "WARN"},
		{"shut down, autostart expected", models.KVMVM{State: models.KVMShutDown, AutoStart: true}, "WARN"},
	}
	for _, c := range cases {
		got := strings.TrimSpace(kvmVMIcon(c.vm, output.ModePlain))
		if got != c.want {
			t.Errorf("%s: kvmVMIcon(%+v) = %q, want %q", c.name, c.vm, got, c.want)
		}
	}
}
