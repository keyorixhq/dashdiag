//go:build linux

package collectors

import "testing"

func TestCgroupThrottledPct(t *testing.T) {
	// Verbatim cpu.stat from a real container (no throttling — idle):
	const idle = "usage_usec 81436\nuser_usec 63912\nsystem_usec 17524\nnice_usec 0\n" +
		"nr_periods 1\nnr_throttled 0\nthrottled_usec 0\nnr_bursts 0\nburst_usec 0\n"
	if got := cgroupThrottledPct(idle); got != 0 {
		t.Errorf("cgroupThrottledPct(idle) = %v, want 0", got)
	}
	// 80 of 100 periods throttled → 80%.
	if got := cgroupThrottledPct("nr_periods 100\nnr_throttled 80\nthrottled_usec 5000\n"); got != 80 {
		t.Errorf("cgroupThrottledPct(throttled) = %v, want 80", got)
	}
	// No periods yet (no CPU limit) → 0, not a divide-by-zero.
	if got := cgroupThrottledPct("nr_periods 0\nnr_throttled 0\n"); got != 0 {
		t.Errorf("cgroupThrottledPct(no periods) = %v, want 0", got)
	}
	if got := cgroupThrottledPct(""); got != 0 {
		t.Errorf("cgroupThrottledPct(empty) = %v, want 0", got)
	}
}

func TestCgroupKeyedValue(t *testing.T) {
	// Verbatim memory.events from a real container.
	const events = "low 0\nhigh 0\nmax 0\noom 0\noom_kill 0\noom_group_kill 0\nsock_throttled 0\n"
	if got := cgroupKeyedValue(events, "oom_kill"); got != 0 {
		t.Errorf("oom_kill = %d, want 0", got)
	}
	if got := cgroupKeyedValue("oom 2\noom_kill 5\n", "oom_kill"); got != 5 {
		t.Errorf("oom_kill = %d, want 5", got)
	}
	// "oom" must not match "oom_kill" (exact key only).
	if got := cgroupKeyedValue("oom_kill 5\n", "oom"); got != 0 {
		t.Errorf("oom = %d, want 0 (must not prefix-match oom_kill)", got)
	}
	if got := cgroupKeyedValue("", "oom_kill"); got != 0 {
		t.Errorf("empty = %d, want 0", got)
	}
}

func TestRootfsWritable(t *testing.T) {
	// Verbatim / line from a real container (overlay, rw).
	const rw = "overlay / overlay rw,relatime,lowerdir=/a:/b,upperdir=/c,workdir=/d 0 0\n" +
		"proc /proc proc rw,nosuid 0 0\n"
	if !rootfsWritable(rw) {
		t.Error("rw overlay root should be writable")
	}
	// Read-only root.
	const ro = "overlay / overlay ro,relatime,lowerdir=/a 0 0\n"
	if rootfsWritable(ro) {
		t.Error("ro root must be reported read-only")
	}
	// No / line → false (don't claim writable when we can't tell).
	if rootfsWritable("proc /proc proc rw 0 0\n") {
		t.Error("no root mount → must not report writable")
	}
}
