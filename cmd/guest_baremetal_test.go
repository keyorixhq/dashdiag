package cmd

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
)

// TestRunGuest_BareMetal covers the detectGuestView found==false branch of
// runGuest. It runs only when no guest environment (container, cloud VM, or
// hypervisor) is detected — i.e. we're on genuine bare metal.
// No t.Parallel() — captureStdout swaps the shared os.Stdout.
func TestRunGuest_BareMetal(t *testing.T) {
	if _, found, err := detectGuestView(context.Background()); found || err != nil {
		t.Skip("skipping: a guest environment was detected (container, VM, or cloud) — not bare metal")
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
