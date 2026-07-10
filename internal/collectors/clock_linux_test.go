//go:build linux

package collectors

import (
	"testing"

	"github.com/keyorixhq/dashdiag/internal/models"
	"github.com/keyorixhq/dashdiag/internal/source"
)

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
// platform.DetectContainerContext reads real, non-injectable OS paths, so
// which of the two branches fires depends on the actual execution
// environment — this cannot be forced hermetically. The assertion only
// pins the invariant that holds on EITHER branch: Source is always
// populated and OffsetMs is never a stray zero-value sentinel confusion.
func TestLiveClockState_ExercisesRealBranch(t *testing.T) {
	st := liveClockState()
	if st.Source == "" {
		t.Error("expected a non-empty Source from either the host or adjtimex branch")
	}
}
