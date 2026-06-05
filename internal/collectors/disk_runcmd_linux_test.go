//go:build linux

package collectors

import (
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
	_, err := runCmdTimeout(200*time.Millisecond, "sleep", "5")
	elapsed := time.Since(start)

	if err == nil {
		t.Error("expected a timeout error, got nil (timeout not enforced)")
	}
	if elapsed > 2*time.Second {
		t.Errorf("runCmdTimeout took %v — timeout not honored", elapsed)
	}
}
