//go:build linux

package collectors

import (
	"context"
	"testing"

	"github.com/keyorixhq/dashdiag/internal/source"
)

// ── collectBootTimes ─────────────────────────────────────────────────────────

func TestCollectBootTimes_Success(t *testing.T) {
	withFixtureSource(t, func(b *source.Bundle) {
		b.PutCmd("systemd-analyze", []string{"time"},
			"Startup finished in 1.234s (kernel) + 5.678s (userspace) = 6.912s\n", 0)
		// blame is sorted descending; parseBlameSlowUnits stops at the first
		// entry under 5.0s (the 1.200s network-online line), so only the two
		// >=5.0s entries surface as slow units.
		b.PutCmd("systemd-analyze", []string{"blame", "--no-pager"},
			"         8.500s NetworkManager-wait-online.service\n"+
				"         5.200s systemd-udev-settle.service\n"+
				"         1.200s some-fast.service\n", 0)
		b.PutCmd("systemctl", []string{"show", "-p", "TriggeredBy", "--value", "NetworkManager-wait-online.service"}, "", 0)
		b.PutCmd("systemctl", []string{"show", "-p", "TriggeredBy", "--value", "systemd-udev-settle.service"}, "", 0)
	})
	units, total := collectBootTimes(context.Background())
	if total != 6.912 {
		t.Errorf("total boot time = %v, want 6.912", total)
	}
	if len(units) != 2 {
		t.Fatalf("expected 2 slow units, got %d: %+v", len(units), units)
	}
}

// TestCollectBootTimes_TimeFails guards the first error return: a failed
// `systemd-analyze time` must short-circuit to (nil, 0) without attempting
// the blame query at all.
func TestCollectBootTimes_TimeFails(t *testing.T) {
	withFixtureSource(t, func(b *source.Bundle) {
		b.PutCmdNotFound("systemd-analyze", []string{"time"})
		b.PutCmd("systemd-analyze", []string{"blame", "--no-pager"}, "should not be called", 0)
	})
	units, total := collectBootTimes(context.Background())
	if units != nil || total != 0 {
		t.Errorf("collectBootTimes = (%+v, %v), want (nil, 0) when systemd-analyze time fails", units, total)
	}
}

// TestCollectBootTimes_BlameFailsStillReturnsTotal guards the second error
// return: a failed blame query must still surface the total boot time already
// parsed, just with a nil slow-unit list — not discard everything.
func TestCollectBootTimes_BlameFailsStillReturnsTotal(t *testing.T) {
	withFixtureSource(t, func(b *source.Bundle) {
		b.PutCmd("systemd-analyze", []string{"time"},
			"Startup finished in 1.000s (kernel) + 2.000s (userspace) = 3.000s\n", 0)
		b.PutCmdNotFound("systemd-analyze", []string{"blame", "--no-pager"})
	})
	units, total := collectBootTimes(context.Background())
	if total != 3.0 {
		t.Errorf("total = %v, want 3.0 (parsed before the blame failure)", total)
	}
	if units != nil {
		t.Errorf("units = %+v, want nil when blame fails", units)
	}
}

// ── timerTriggeredExcluder ───────────────────────────────────────────────────

func TestTimerTriggeredExcluder_TimerTriggered(t *testing.T) {
	withFixtureSource(t, func(b *source.Bundle) {
		b.PutCmd("systemctl", []string{"show", "-p", "TriggeredBy", "--value", "apt-daily-upgrade.service"},
			"TriggeredBy=apt-daily-upgrade.timer\n", 0)
	})
	excluder := timerTriggeredExcluder(context.Background())
	if !excluder("apt-daily-upgrade.service") {
		t.Error("expected true for a unit triggered by a .timer")
	}
}

func TestTimerTriggeredExcluder_NotTimerTriggered(t *testing.T) {
	withFixtureSource(t, func(b *source.Bundle) {
		b.PutCmd("systemctl", []string{"show", "-p", "TriggeredBy", "--value", "sshd.service"}, "", 0)
	})
	excluder := timerTriggeredExcluder(context.Background())
	if excluder("sshd.service") {
		t.Error("expected false for a unit with no TriggeredBy timer")
	}
}

// TestTimerTriggeredExcluder_QueryFailsOpen guards the fail-open contract: a
// systemctl query error must return false (unit kept, not hidden) so a
// genuine boot offender is never silently excluded just because systemctl
// couldn't be queried.
func TestTimerTriggeredExcluder_QueryFailsOpen(t *testing.T) {
	withFixtureSource(t, func(b *source.Bundle) {
		b.PutCmdNotFound("systemctl", []string{"show", "-p", "TriggeredBy", "--value", "mystery.service"})
	})
	excluder := timerTriggeredExcluder(context.Background())
	if excluder("mystery.service") {
		t.Error("expected false (fail open, unit kept) when systemctl can't be queried")
	}
}
