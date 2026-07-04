//go:build linux

package collectors

import (
	"testing"

	"github.com/keyorixhq/dashdiag/internal/models"
	"github.com/keyorixhq/dashdiag/internal/source"
)

// TestDetectSessionModeReplaysCapturedEnv guards a replay-hermeticity gap:
// detectSessionMode's Game-Mode-vs-Desktop-Mode verdict (models.SteamOSInfo.
// SessionMode) must reflect the CAPTURED host's XDG_SESSION_DESKTOP, not the
// replaying machine's own session — otherwise a Steam Deck bundle captured in
// Game Mode would render as "desktop"/"unknown" when replayed from any shell
// that isn't itself a gamescope session (i.e. every normal replay).
func TestDetectSessionModeReplaysCapturedEnv(t *testing.T) {
	t.Setenv("XDG_SESSION_DESKTOP", "gamescope")

	rec := source.NewRecorder(source.Live{})
	prev := SetSource(rec)
	gotLive := detectSessionMode(&models.SteamOSInfo{})
	SetSource(prev)
	if gotLive != "gamemode" {
		t.Fatalf("detectSessionMode during capture = %q, want %q", gotLive, "gamemode")
	}

	// The replaying shell is a plain desktop session, not gamescope.
	t.Setenv("XDG_SESSION_DESKTOP", "plasma")

	defer SetSource(SetSource(source.NewReplay(rec.Bundle())))
	gotReplay := detectSessionMode(&models.SteamOSInfo{})
	if gotReplay != "gamemode" {
		t.Fatalf("detectSessionMode on replay = %q, want recorded %q (leaked the replaying machine's session)", gotReplay, "gamemode")
	}
}
