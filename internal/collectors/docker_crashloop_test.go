//go:build linux || darwin

package collectors

import (
	"testing"
	"time"
)

// TestCrashLoopStabilized verifies the recency gate that stops a container's
// cumulative RestartCount from emitting a perpetual crash-loop CRIT once it has
// recovered (running continuously past the stable window).
func TestCrashLoopStabilized(t *testing.T) {
	now := time.Now()
	cases := []struct {
		name      string
		running   bool
		startedAt time.Time
		want      bool
	}{
		{"running and up well past window — stabilized", true, now.Add(-30 * time.Minute), true},
		{"running but only just (re)started — not yet stable", true, now.Add(-30 * time.Second), false},
		{"not running (still crashing/restarting)", false, now.Add(-30 * time.Minute), false},
		{"running but zero/unparsed StartedAt — cannot confirm", true, time.Time{}, false},
		{"running exactly at the window edge (under)", true, now.Add(-(crashLoopStableWindow - time.Second)), false},
	}
	for _, c := range cases {
		if got := crashLoopStabilized(c.running, c.startedAt); got != c.want {
			t.Errorf("%s: crashLoopStabilized(%v, %v) = %v, want %v",
				c.name, c.running, c.startedAt, got, c.want)
		}
	}
}
