//go:build !darwin

package collectors

import (
	"context"
	"testing"
	"time"
)

// TestLaunchdCollector_NotDarwin guards the Linux/other stub: Launchd is
// macOS-only, so on every other platform Collect must be an immediate no-op
// (nil, nil) with no side effects, while Name/Timeout stay identical to the
// darwin variant so render/drilldown keying doesn't drift per platform.
func TestLaunchdCollector_NotDarwin(t *testing.T) {
	t.Parallel()
	c := NewLaunchdCollector()
	if c.Name() != "Launchd" {
		t.Errorf("Name() = %q, want Launchd", c.Name())
	}
	if c.Timeout() != 2*time.Second {
		t.Errorf("Timeout() = %v, want 2s", c.Timeout())
	}
	raw, err := c.Collect(context.Background())
	if err != nil {
		t.Fatalf("Collect() error: %v, want nil", err)
	}
	if raw != nil {
		t.Errorf("Collect() raw = %+v, want nil (Launchd is macOS-only)", raw)
	}
}
