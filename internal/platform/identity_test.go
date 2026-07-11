package platform

import (
	"os"
	"testing"
)

// TestSetIdentity guards the replay identity override: while set, Hostname() and
// OSPrettyName() report the captured host (so a replayed report / dsd diff carries
// the right host, not the replaying machine); restore() reverts to the live values.
func TestSetIdentity(t *testing.T) {
	live, _ := os.Hostname()

	restore := SetIdentity("captured-host", "Captured OS 1.0")
	if got := Hostname(); got != "captured-host" {
		t.Errorf("Hostname() under override = %q, want captured-host", got)
	}
	if got := OSPrettyName(); got != "Captured OS 1.0" {
		t.Errorf("OSPrettyName() under override = %q, want Captured OS 1.0", got)
	}

	restore()
	if got := Hostname(); got != live {
		t.Errorf("Hostname() after restore = %q, want live %q", got, live)
	}
	if OSPrettyName() == "Captured OS 1.0" {
		t.Error("OSPrettyName() still returns the override after restore")
	}

	// Empty override leaves the field reading live.
	r2 := SetIdentity("", "")
	defer r2()
	if got := Hostname(); got != live {
		t.Errorf("empty override should read live hostname, got %q", got)
	}
}

// TestSetReplayPlatform guards the `dsd replay` distro/init/GOOS pin: while set,
// the Replay* getters report the captured host's values so fix-hints adapt to
// the CAPTURED host, not the box doing the replay; restore() reverts to "" (live).
func TestSetReplayPlatform(t *testing.T) {
	t.Parallel()
	if got := ReplayDistroID(); got != "" {
		t.Errorf("ReplayDistroID() with no override = %q, want empty", got)
	}
	if got := ReplayInitSystem(); got != "" {
		t.Errorf("ReplayInitSystem() with no override = %q, want empty", got)
	}
	if got := ReplayGOOS(); got != "" {
		t.Errorf("ReplayGOOS() with no override = %q, want empty", got)
	}

	restore := SetReplayPlatform("rhel", "systemd", "linux")
	if got := ReplayDistroID(); got != "rhel" {
		t.Errorf("ReplayDistroID() under override = %q, want rhel", got)
	}
	if got := ReplayInitSystem(); got != "systemd" {
		t.Errorf("ReplayInitSystem() under override = %q, want systemd", got)
	}
	if got := ReplayGOOS(); got != "linux" {
		t.Errorf("ReplayGOOS() under override = %q, want linux", got)
	}

	// Nested override + restore must return to the PREVIOUS override, not
	// unconditionally to "".
	restore2 := SetReplayPlatform("ubuntu", "systemd", "linux")
	if got := ReplayDistroID(); got != "ubuntu" {
		t.Errorf("ReplayDistroID() under nested override = %q, want ubuntu", got)
	}
	restore2()
	if got := ReplayDistroID(); got != "rhel" {
		t.Errorf("ReplayDistroID() after inner restore = %q, want rhel (outer override)", got)
	}

	restore()
	if got := ReplayDistroID(); got != "" {
		t.Errorf("ReplayDistroID() after restore = %q, want empty", got)
	}
	if got := ReplayInitSystem(); got != "" {
		t.Errorf("ReplayInitSystem() after restore = %q, want empty", got)
	}
	if got := ReplayGOOS(); got != "" {
		t.Errorf("ReplayGOOS() after restore = %q, want empty", got)
	}
}
