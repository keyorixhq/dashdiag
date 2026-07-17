package cmd

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/keyorixhq/dashdiag/internal/collectors"
)

// TestRunGuest_BareMetal covers the detectGuestView found==false branch of
// runGuest. This test is the counterpart to TestRunGuest (which skips when
// ContainerGuestAvailable returns false). It runs on any non-container host
// (macOS, GitHub Actions Ubuntu runner without a guest hypervisor layer, etc.)
// and verifies that runGuest correctly returns a "bare metal" message in plain
// mode and a {"in_guest":false} object in JSON mode.
// No t.Parallel() — captureStdout swaps the shared os.Stdout.
func TestRunGuest_BareMetal(t *testing.T) {
	if collectors.ContainerGuestAvailable() {
		t.Skip("skipping bare-metal test when running inside a container")
	}

	// plain mode: should print a "bare metal" info line
	plainCmd := newBareCloudCmd()
	_ = plainCmd.Flags().Set("plain", "true")
	plainOut := captureStdout(t, func() {
		if err := runGuest(plainCmd, nil); err != nil {
			t.Fatalf("runGuest (plain, bare metal): %v", err)
		}
	})
	if !strings.Contains(plainOut, "bare metal") {
		t.Errorf("plain mode on non-container host should say 'bare metal', got %q", plainOut)
	}

	// json mode: should emit {"in_guest":false,...}
	jsonCmd := newBareCloudCmd()
	_ = jsonCmd.Flags().Set("json", "true")
	jsonOut := captureStdout(t, func() {
		if err := runGuest(jsonCmd, nil); err != nil {
			t.Fatalf("runGuest (json, bare metal): %v", err)
		}
	})
	var obj map[string]any
	if err := json.Unmarshal([]byte(strings.TrimSpace(jsonOut)), &obj); err != nil {
		t.Fatalf("json mode should emit valid JSON, got %q: %v", jsonOut, err)
	}
	if v, ok := obj["in_guest"]; !ok || v != false {
		t.Errorf("json mode bare-metal should have in_guest=false, got %v", obj)
	}
}
