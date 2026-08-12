//go:build linux

package collectors

import (
	"testing"

	"github.com/keyorixhq/dashdiag/internal/models"
	"github.com/keyorixhq/dashdiag/internal/source"
)

// TestCollectLinux_LiveCachedClosure covers clock.go:75.72,77.3 — the
// produce-function closure passed to Cached. source.Live always calls produce
// rather than looking up a recorded value, so the closure body executes and
// records the live clock state.
func TestCollectLinux_LiveCachedClosure(t *testing.T) {
	// no t.Parallel(): SetSource mutates the package-level activeSource.
	prev := SetSource(source.Live{})
	t.Cleanup(func() { SetSource(prev) })

	info := &models.ClockInfo{}
	if _, err := (&ClockCollector{}).collectLinux(info); err != nil {
		t.Fatalf("collectLinux with Live source: %v", err)
	}
	if info.Source == "" {
		t.Error("expected non-empty Source from live collectLinux")
	}
}

// TestCollectLinux_RTCInLocalTZ guards the /etc/adjtime-derived RTCInLocalTZ
// flag: a file containing "LOCAL" must set it true, a file without "LOCAL"
// (the standard UTC RTC configuration) must leave it false, and an absent
// file (readFile error, e.g. no /etc/adjtime at all) must also leave it
// false rather than erroring the whole collect.
func TestCollectLinux_RTCInLocalTZ(t *testing.T) {
	t.Run("RTC in local timezone", func(t *testing.T) {
		withFixtureSource(t, func(b *source.Bundle) {
			b.PutFile("/etc/adjtime", []byte("0.0 0 0.0\n0\nLOCAL\n"))
		})
		info := &models.ClockInfo{}
		if _, err := (&ClockCollector{}).collectLinux(info); err != nil {
			t.Fatalf("collectLinux: %v", err)
		}
		if !info.RTCInLocalTZ {
			t.Error("expected RTCInLocalTZ=true when /etc/adjtime contains LOCAL")
		}
	})

	t.Run("RTC in UTC", func(t *testing.T) {
		withFixtureSource(t, func(b *source.Bundle) {
			b.PutFile("/etc/adjtime", []byte("0.0 0 0.0\n0\nUTC\n"))
		})
		info := &models.ClockInfo{}
		if _, err := (&ClockCollector{}).collectLinux(info); err != nil {
			t.Fatalf("collectLinux: %v", err)
		}
		if info.RTCInLocalTZ {
			t.Error("expected RTCInLocalTZ=false when /etc/adjtime does not contain LOCAL")
		}
	})

	t.Run("adjtime file absent", func(t *testing.T) {
		withFixtureSource(t, func(_ *source.Bundle) {}) // /etc/adjtime never seeded
		info := &models.ClockInfo{}
		if _, err := (&ClockCollector{}).collectLinux(info); err != nil {
			t.Fatalf("collectLinux: %v", err)
		}
		if info.RTCInLocalTZ {
			t.Error("expected RTCInLocalTZ=false when /etc/adjtime is absent")
		}
	})
}

// TestLiveClockState_ExercisesRealBranch calls liveClockState directly
// (unlike collectLinux's Cached-wrapped call) to attribute its own coverage.
// liveClockState always reads the real kernel clock via adjtimex(2) — the
// container-vs-bare-metal distinction was removed (internal-collectors-03-02:
// it used to assume a container's clock is synced rather than measuring it),
// so Source now always comes from adjtimexSync's own outcomes.
func TestLiveClockState_ExercisesRealBranch(t *testing.T) {
	st := liveClockState()
	if st.Source == "" {
		t.Error("expected a non-empty Source from adjtimexSync")
	}
}
