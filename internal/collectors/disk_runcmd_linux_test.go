//go:build linux

package collectors

import (
	"context"
	"testing"
	"time"
)

// TestRunCmdTimeoutHonored guards that runCmdTimeout actually enforces its
// timeout (it previously discarded it, leaving smartctl/zpool/virsh able to hang
// all of dsd health). `sleep 5` under a 200ms budget must return promptly with
// an error.
func TestRunCmdTimeoutHonored(t *testing.T) {
	t.Parallel()
	start := time.Now()
	_, err := runCmdTimeout(context.Background(), 200*time.Millisecond, "sleep", "5")
	elapsed := time.Since(start)

	if err == nil {
		t.Error("expected a timeout error, got nil (timeout not enforced)")
	}
	if elapsed > 2*time.Second {
		t.Errorf("runCmdTimeout took %v — timeout not honored", elapsed)
	}
}

// TestRunCmdTimeoutHonorsParentCancellation guards subprocess-wrappers-04:
// runCmdTimeout previously built its own context.WithTimeout(context.
// Background(), timeout) internally, decoupled from any caller cancellation —
// the exact anti-pattern CLAUDE.md documents ("Context must be propagated,
// never re-created"). If the CALLER's context is already cancelled (e.g. the
// runner cancelled the whole collector), the command must be cut short
// immediately rather than running to its own independent per-call timeout.
func TestRunCmdTimeoutHonorsParentCancellation(t *testing.T) {
	t.Parallel()
	parent, cancel := context.WithCancel(context.Background())
	cancel() // already cancelled before the command ever starts

	start := time.Now()
	_, err := runCmdTimeout(parent, 5*time.Second, "sleep", "5")
	elapsed := time.Since(start)

	if err == nil {
		t.Error("expected an error when the parent context is already cancelled, got nil")
	}
	if elapsed > 2*time.Second {
		t.Errorf("runCmdTimeout took %v with an already-cancelled parent — want it to return promptly, not run toward its own 5s timeout", elapsed)
	}
}
