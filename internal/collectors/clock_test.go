package collectors

import (
	"context"
	"encoding/json"
	"runtime"
	"testing"
	"time"

	"github.com/keyorixhq/dashdiag/internal/models"
	"github.com/keyorixhq/dashdiag/internal/source"
)

// TestNewClockCollector_Identity pins the constructor and identity methods
// (Name/Timeout) — these touch no fixture source, so t.Parallel() is safe.
func TestNewClockCollector_Identity(t *testing.T) {
	t.Parallel()
	c := NewClockCollector()
	if c == nil {
		t.Fatal("NewClockCollector returned nil")
	}
	if got, want := c.Name(), "Clock"; got != want {
		t.Errorf("Name() = %q, want %q", got, want)
	}
	if got, want := c.Timeout(), 2*time.Second; got != want {
		t.Errorf("Timeout() = %v, want %v", got, want)
	}
}

func TestClockCollector_ReturnsResult(t *testing.T) {
	t.Parallel()
	c := NewClockCollector()
	result, err := c.Collect(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result == nil {
		t.Fatal("expected non-nil result")
	}
	if _, ok := result.(*models.ClockInfo); !ok {
		t.Fatalf("expected *models.ClockInfo, got %T", result)
	}
}

func TestAdjtimexSync_Linux(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("adjtimex only on Linux")
	}
	t.Parallel()
	synced, offsetMs, source := adjtimexSync()
	if source == "" {
		t.Error("source must not be empty")
	}
	// On a healthy system with NTP, synced should be true.
	// We don't assert synced==true because CI hosts may not have NTP.
	t.Logf("adjtimex: synced=%v offsetMs=%.3f source=%s", synced, offsetMs, source)
}

// TestClockReplayReproducesCapturedSyncState guards the replay-fidelity gap found
// on the VMware Debian capture: the host was live "NTP not synchronized" (CRIT),
// but replaying the bundle inside a container reported "host: synced" (OK) because
// the container short-circuit and the adjtimex(2) syscall were read live at replay
// time, not captured. With the clock/state key recorded, replay must reproduce the
// CAPTURED unsynced verdict regardless of the replaying machine's own clock.
func TestClockReplayReproducesCapturedSyncState(t *testing.T) {
	rec := source.NewRecorder(source.Live{})
	captured := clockState{Synced: false, OffsetMs: -1, Source: "adjtimex"}
	blob, err := json.Marshal(captured)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if _, err := rec.Cached("clock/state", func() ([]byte, error) { return blob, nil }); err != nil {
		t.Fatalf("seed record: %v", err)
	}

	prev := SetSource(source.NewReplay(rec.Bundle()))
	defer SetSource(prev)

	info := &models.ClockInfo{}
	if _, err := (&ClockCollector{}).collectLinux(info); err != nil {
		t.Fatalf("collectLinux: %v", err)
	}
	if info.Synced {
		t.Error("replay reported Synced=true, but the captured state was unsynced — replay is not hermetic")
	}
	if info.Source != "adjtimex" {
		t.Errorf("replay Source = %q, want captured %q", info.Source, "adjtimex")
	}
}
