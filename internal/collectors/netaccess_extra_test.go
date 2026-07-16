//go:build linux

package collectors

// netaccess_extra_test.go — additional branch coverage for netaccess.go
// paths not covered by netaccess_test.go (which has no build tag and
// therefore cannot use Linux-only withCombinedFixture/withFixtureSource).

import (
	"testing"
	"time"
)

// TestDialOutcome_PermissionDenied drives the dialPermission branch in
// dialOutcome: when the Cached closure's derr contains "permission denied",
// the stored byte is 'p' and the result is dialPermission.
// We inject the pre-recorded result via withCombinedFixture so the closure
// never runs — instead we seed 'p' directly into the Cached key, which is
// what dialOutcome writes on a permission-denied error.
func TestDialOutcome_PermissionDenied(t *testing.T) {
	// Not parallel: withCombinedFixture swaps the package-level activeSource.
	// Seed the Cached key with the 'p' byte that dialOutcome writes on
	// a permission-denied error — this exercises the switch case 'p' → dialPermission.
	withCombinedFixture(t, map[string][]byte{
		"dial/tcp/127.0.0.1:1": {'p'},
	}, nil, nil)
	got := dialOutcome("tcp", "127.0.0.1:1", 200*time.Millisecond)
	if got != dialPermission {
		t.Errorf("dialOutcome() = %v, want dialPermission", got)
	}
}

// TestDialOutcome_UnknownByte drives the default branch in dialOutcome's
// switch: a recorded byte that is neither '1', 'p', nor '0' must map to
// dialUnreachable (the safe default).
func TestDialOutcome_UnknownByte(t *testing.T) {
	// Not parallel: withCombinedFixture swaps the package-level activeSource.
	withCombinedFixture(t, map[string][]byte{
		"dial/tcp/127.0.0.1:2": {'x'},
	}, nil, nil)
	got := dialOutcome("tcp", "127.0.0.1:2", 200*time.Millisecond)
	if got != dialUnreachable {
		t.Errorf("dialOutcome() = %v, want dialUnreachable for unknown byte 'x'", got)
	}
}

// TestDialOutcome_EmptyData drives the "len(data) != 1" guard: when the
// Cached key returns empty bytes (recording gap / corrupted entry), the
// result must be dialUnreachable.
func TestDialOutcome_EmptyData(t *testing.T) {
	// Not parallel: withCombinedFixture swaps the package-level activeSource.
	withCombinedFixture(t, map[string][]byte{
		"dial/tcp/127.0.0.1:3": {},
	}, nil, nil)
	got := dialOutcome("tcp", "127.0.0.1:3", 200*time.Millisecond)
	if got != dialUnreachable {
		t.Errorf("dialOutcome() = %v, want dialUnreachable for empty data", got)
	}
}
