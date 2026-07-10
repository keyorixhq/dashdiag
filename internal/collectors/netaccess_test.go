package collectors

import (
	"net"
	"testing"
	"time"
)

// TestDialOutcome_Unreachable drives dialOutcome's real net.DialTimeout error
// path (derr != nil, not a "permission denied" error) with a TCP port nothing
// listens on — loopback routing needs no external network, so this is
// deterministic. Uses the real activeSource (source.Live) so the live dial
// closure actually runs, unlike the withCombinedFixture-based tests
// elsewhere that intercept Cached directly and never reach it.
func TestDialOutcome_Unreachable(t *testing.T) {
	t.Parallel()
	// Port 1 is a reserved/unassigned TCP port; nothing listens on loopback.
	got := dialOutcome("tcp", "127.0.0.1:1", 200*time.Millisecond)
	if got != dialUnreachable {
		t.Errorf("dialOutcome() = %v, want dialUnreachable", got)
	}
}

// TestDialOutcome_OK drives the successful-dial branch directly (not via a
// Cached-intercepting fixture), confirming the real net.DialTimeout success
// path returns dialOK.
func TestDialOutcome_OK(t *testing.T) {
	t.Parallel()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to listen: %v", err)
	}
	defer ln.Close() //nolint:errcheck

	got := dialOutcome("tcp", ln.Addr().String(), time.Second)
	if got != dialOK {
		t.Errorf("dialOutcome() = %v, want dialOK", got)
	}
}
