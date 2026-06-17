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
