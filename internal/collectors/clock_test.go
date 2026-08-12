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

// TestLiveClockState_NeverAssumesHostSynced is a regression guard for
// internal-collectors-03-02: liveClockState used to short-circuit to
// Synced:true/Source:"host" for every container, on the (unmeasured)
// assumption that "the host presumably handles this" — reported identically
// to a genuinely verified sync. adjtimex(2) reads the same shared,
// non-namespaced kernel clock state whether or not the caller is in a
// container, so Source must always come from adjtimexSync's real outcomes
// ("adjtimex" or "unavailable") — never the old "host" sentinel, regardless
// of whether this test happens to run inside a container itself.
func TestLiveClockState_NeverAssumesHostSynced(t *testing.T) {
	got := liveClockState()
	if got.Source == "host" {
		t.Errorf("liveClockState must never assume host-sync via the old container short-circuit, got %+v", got)
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

// TestClockCollector_CollectDarwin_PgrepFound covers clock.go:29.98,34.57 and
// clock.go:34.57,37.3 — the `if _, err := runCmd(ctx, "pgrep", "timed"); err == nil`
// success branch, which sets Synced=true and Source="timed".
func TestClockCollector_CollectDarwin_PgrepFound(t *testing.T) {
	b := source.NewBundle()
	b.PutCmd("pgrep", []string{"timed"}, "", 0)
	prev := SetSource(source.NewReplay(b))
	defer SetSource(prev)

	info := &models.ClockInfo{}
	result, err := (&ClockCollector{}).collectDarwin(context.Background(), info)
	if err != nil {
		t.Fatalf("collectDarwin returned error: %v", err)
	}
	got, ok := result.(*models.ClockInfo)
	if !ok {
		t.Fatalf("result is not *models.ClockInfo, got %T", result)
	}
	if !got.Synced {
		t.Error("expected Synced=true when pgrep timed succeeds")
	}
	if got.Source != "timed" {
		t.Errorf("Source = %q, want %q", got.Source, "timed")
	}
	if got.OffsetMs != -1 {
		t.Errorf("OffsetMs = %v, want -1 (darwin has no offset)", got.OffsetMs)
	}
}

// TestClockCollector_CollectDarwin_PgrepMissing covers clock.go:37.8,40.3 and
// clock.go:41.2,41.18 — the else branch when pgrep timed fails (timed not running),
// which sets Synced=false and Source="unavailable".
func TestClockCollector_CollectDarwin_PgrepMissing(t *testing.T) {
	b := source.NewBundle()
	b.PutCmd("pgrep", []string{"timed"}, "", 1) // non-zero exit → not running
	prev := SetSource(source.NewReplay(b))
	defer SetSource(prev)

	info := &models.ClockInfo{}
	result, err := (&ClockCollector{}).collectDarwin(context.Background(), info)
	if err != nil {
		t.Fatalf("collectDarwin returned error: %v", err)
	}
	got, ok := result.(*models.ClockInfo)
	if !ok {
		t.Fatalf("result is not *models.ClockInfo, got %T", result)
	}
	if got.Synced {
		t.Error("expected Synced=false when pgrep timed fails")
	}
	if got.Source != "unavailable" {
		t.Errorf("Source = %q, want %q", got.Source, "unavailable")
	}
}
