//go:build linux

package collectors

import (
	"testing"

	"github.com/keyorixhq/dashdiag/internal/source"
)

// seedDialOutcome records a dialOutcome result for network/addr via a Recorder
// and installs a Replay source over the resulting bundle, so detectContainerdSocket
// sees a deterministic outcome without touching a real socket.
func seedDialOutcome(t *testing.T, network, addr string, b byte) {
	t.Helper()
	rec := source.NewRecorder(source.Live{})
	key := "dial/" + network + "/" + addr
	if _, err := rec.Cached(key, func() ([]byte, error) { return []byte{b}, nil }); err != nil {
		t.Fatalf("seed %s: %v", key, err)
	}
	prev := SetSource(source.NewReplay(rec.Bundle()))
	t.Cleanup(func() { SetSource(prev) })
}

// TestDetectContainerdSocket_PermissionDenied is a regression guard: a
// permission-denied dial (0660 root:root socket, non-root dsd) used to
// collapse into "unreachable" — indistinguishable from containerd simply not
// being installed. detectContainerdSocket must report the socket path AND
// that it was permission-denied, not just an empty path.
func TestDetectContainerdSocket_PermissionDenied(t *testing.T) {
	seedDialOutcome(t, "unix", containerdSocketCandidates[0], 'p')

	path, permDenied := detectContainerdSocket()
	if path != containerdSocketCandidates[0] {
		t.Errorf("path = %q, want %q", path, containerdSocketCandidates[0])
	}
	if !permDenied {
		t.Error("permDenied = false, want true")
	}
	if !ContainerdAvailable() {
		t.Error("ContainerdAvailable() must be true for a present-but-denied socket — containerd is installed, not absent")
	}
}

// TestDetectContainerdSocket_GenuinelyAbsent confirms the "not installed"
// case is unaffected: both candidates unreachable → empty path, not denied.
func TestDetectContainerdSocket_GenuinelyAbsent(t *testing.T) {
	for _, c := range containerdSocketCandidates {
		seedDialOutcome(t, "unix", c, '0')
	}
	path, permDenied := detectContainerdSocket()
	if path != "" || permDenied {
		t.Errorf("got (%q, %v), want (\"\", false)", path, permDenied)
	}
	if ContainerdAvailable() {
		t.Error("ContainerdAvailable() must be false when genuinely absent")
	}
}
