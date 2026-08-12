//go:build linux

package collectors

import (
	"context"
	"testing"
	"time"

	"github.com/keyorixhq/dashdiag/internal/source"
)

func TestAptDBHealth_Clean(t *testing.T) {
	withFixtureSource(t, func(b *source.Bundle) {
		b.PutCmd("dpkg", []string{"--audit"}, "", 0)
	})
	checked, blocked, reason, fix := aptDBHealth(context.Background())
	if !checked || blocked {
		t.Errorf("expected checked=true blocked=false for empty dpkg --audit, got checked=%v blocked=%v", checked, blocked)
	}
	if reason != "" || fix != "" {
		t.Errorf("expected no reason/fix on a clean DB, got reason=%q fix=%q", reason, fix)
	}
}

func TestAptDBHealth_Blocked(t *testing.T) {
	withFixtureSource(t, func(b *source.Bundle) {
		b.PutCmd("dpkg", []string{"--audit"}, "foo is in a very bad inconsistent state\n", 0)
	})
	checked, blocked, reason, fix := aptDBHealth(context.Background())
	if !checked || !blocked {
		t.Fatalf("expected checked=true blocked=true for non-empty dpkg --audit, got checked=%v blocked=%v", checked, blocked)
	}
	if reason == "" || fix == "" {
		t.Error("expected a non-empty reason and fix command when the dpkg DB is blocked")
	}
}

func TestAptDBHealth_DpkgUnusable(t *testing.T) {
	withFixtureSource(t, func(b *source.Bundle) {
		b.PutCmdNotFound("dpkg", []string{"--audit"})
	})
	checked, blocked, _, _ := aptDBHealth(context.Background())
	if checked || blocked {
		t.Errorf("expected checked=false blocked=false (couldn't measure) when dpkg is unusable, got checked=%v blocked=%v", checked, blocked)
	}
}

func TestRpmDBHealth_NoRPMTool(t *testing.T) {
	withLookPathFixture(t, map[string]bool{}, func(b *source.Bundle) {})
	checked, blocked, _, _ := rpmDBHealth(context.Background())
	if checked || blocked {
		t.Errorf("expected checked=false blocked=false (couldn't measure) when rpm is absent, got checked=%v blocked=%v", checked, blocked)
	}
}

func TestRpmDBHealth_Clean(t *testing.T) {
	withLookPathFixture(t, map[string]bool{"rpm": true}, func(b *source.Bundle) {
		b.PutCmd("rpm", []string{"-q", "rpm"}, "rpm-4.18.2-1.el9.x86_64\n", 0)
	})
	checked, blocked, _, _ := rpmDBHealth(context.Background())
	if !checked || blocked {
		t.Errorf("expected checked=true blocked=false for a healthy rpmdb, got checked=%v blocked=%v", checked, blocked)
	}
}

// countingRPMSource returns a distinct outcome for each successive "rpm -q
// rpm" invocation, letting the test drive rpmDBHealth's retry-after-1.5s
// transient-lock path deterministically.
type countingRPMSource struct {
	source.Source
	outcomes []source.Result
	calls    int
}

func (c *countingRPMSource) Cached(key string, _ func() ([]byte, error)) ([]byte, error) {
	if key == "lookpath/rpm" {
		return []byte("/usr/bin/rpm"), nil
	}
	return nil, errNotFoundCVE
}

func (c *countingRPMSource) Run(_ context.Context, name string, _ ...string) (source.Result, error) {
	if name != "rpm" || c.calls >= len(c.outcomes) {
		return source.Result{}, nil
	}
	r := c.outcomes[c.calls]
	c.calls++
	return r, nil
}

// TestRpmDBHealth_TransientLockClearsOnRetry guards the false-"corrupt"-alarm
// fix: a single failed rpm -q rpm (common ~1s post-boot lock from
// dnf-makecache.timer/PackageKit) must not report blocked=true — it must
// retry once and clear. Real ~1.5s wall-clock wait (sleepCtx), not mocked.
func TestRpmDBHealth_TransientLockClearsOnRetry(t *testing.T) {
	fake := &countingRPMSource{outcomes: []source.Result{
		{ExitCode: 1}, // first probe: transient lock
		{ExitCode: 0}, // retry: cleared
	}}
	defer SetSource(SetSource(fake))

	checked, blocked, _, _ := rpmDBHealth(context.Background())
	if !checked || blocked {
		t.Errorf("expected checked=true blocked=false after the transient lock clears, got checked=%v blocked=%v", checked, blocked)
	}
}

func TestRpmDBHealth_PersistentlyBlocked(t *testing.T) {
	fake := &countingRPMSource{outcomes: []source.Result{
		{ExitCode: 1},
		{ExitCode: 1},
	}}
	defer SetSource(SetSource(fake))

	checked, blocked, reason, fix := rpmDBHealth(context.Background())
	if !checked || !blocked {
		t.Errorf("expected checked=true blocked=true when both probes fail, got checked=%v blocked=%v", checked, blocked)
	}
	if reason == "" || fix == "" {
		t.Error("expected a non-empty reason and fix command when the rpmdb is persistently blocked")
	}
}

// TestRpmDBHealth_ContextCancelledDuringWait guards the partial-probe guard:
// if ctx is cancelled while waiting out the retry delay, rpmDBHealth must NOT
// assert blocked=true off an incomplete probe — and must report checked=false
// ("couldn't measure"), not checked=true, since only one failed probe ran and
// there was no time for the confirming retry that tells a transient lock from
// a real block apart (BUG-088-class conflation: checked=true,blocked=false
// asserts a clean DB from a probe that never got to confirm it).
func TestRpmDBHealth_ContextCancelledDuringWait(t *testing.T) {
	fake := &countingRPMSource{outcomes: []source.Result{
		{ExitCode: 1}, // first probe fails, triggering the wait-then-retry path
	}}
	defer SetSource(SetSource(fake))

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Millisecond)
	defer cancel()

	checked, blocked, _, _ := rpmDBHealth(ctx)
	if checked || blocked {
		t.Errorf("expected checked=false blocked=false when ctx cancels mid-wait (partial probe, no confirming retry), got checked=%v blocked=%v", checked, blocked)
	}
}
