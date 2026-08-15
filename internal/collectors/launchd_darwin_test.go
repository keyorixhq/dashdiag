//go:build darwin

package collectors

import (
	"testing"

	"github.com/keyorixhq/dashdiag/internal/source"
)

const launchctlOutput = `PID	Status	Label
1234	-	com.apple.Spotlight
-	0	com.apple.screensaver.engine
-	1	com.example.myapp
-	127	com.example.crasher
-	0	com.apple.security.keychain-circle-notification
789	-	com.homebrew.mySQLd
-	1	application.com.google.Chrome.123.456
`

func TestParseLaunchctlList(t *testing.T) {
	total, running, failed := parseLaunchctlList(launchctlOutput)

	// Filtered: com.apple.* (3 entries) + application.* (1 entry) = 4 noise entries
	// Remaining: myapp (failed), crasher (failed), mySQLd (running) = 3
	if total != 3 {
		t.Errorf("total = %d, want 3 (apple.* and application.* filtered)", total)
	}
	if running != 1 {
		t.Errorf("running = %d, want 1 (mySQLd only)", running)
	}
	if len(failed) != 2 {
		t.Errorf("failed = %d, want 2 (myapp + crasher)", len(failed))
	}
	if failed[0].Label != "com.example.myapp" {
		t.Errorf("failed[0].Label = %q, want com.example.myapp", failed[0].Label)
	}
	if failed[0].Status != 1 {
		t.Errorf("failed[0].Status = %d, want 1", failed[0].Status)
	}
	if failed[1].Status != 127 {
		t.Errorf("failed[1].Status = %d, want 127", failed[1].Status)
	}
}

func TestIsLaunchdNoise(t *testing.T) {
	// Everything Apple-prefixed is noise — all variants
	noisy := []string{
		"com.apple.security.keychain-circle-notification",
		"com.apple.xpc.launchd.oneshot",
		"com.apple.system.logger",
		"com.apple.Spotlight",
		"com.apple.cloudphotod",
		"com.apple.knowledgeconstructiond",
		"com.apple.progressd",
		"application.com.google.Chrome.123.456",
		"application.com.anthropic.claudefordesktop.70000441.70000447",
	}
	// Third-party daemons are signal — not noise
	signal := []string{
		"com.example.myapp",
		"com.homebrew.postgresql",
		"org.nginx.nginx",
		"com.docker.docker",
		"io.tailscale.ipn.macos",
		"com.microsoft.teams2.agent",
	}
	for _, label := range noisy {
		if !isLaunchdNoise(label) {
			t.Errorf("isLaunchdNoise(%q) = false, want true", label)
		}
	}
	for _, label := range signal {
		if isLaunchdNoise(label) {
			t.Errorf("isLaunchdNoise(%q) = true, want false", label)
		}
	}
}

// TestParseLaunchctlList_SpoofedAppleFailureNotSuppressed is the regression
// test for internal-collectors-18-08: a "com.apple." label with no matching
// plist under the system launchd directories is a spoofed persistence item,
// not Apple's own on-demand-daemon noise — it must surface as a real failure,
// not be silently swallowed by the prefix-based suppression.
func TestParseLaunchctlList_SpoofedAppleFailureNotSuppressed(t *testing.T) {
	// No PutStat seeded for either system dir → statFile returns
	// ErrNotRecorded for both candidate paths, same as "no plist there".
	withDarwinFixtureSource(t, func(b *source.Bundle) {})

	out := "PID\tStatus\tLabel\n" +
		"-\t1\tcom.apple.zzclaudetest\n"
	total, running, failed := parseLaunchctlList(out)

	if total != 1 {
		t.Errorf("total = %d, want 1 (spoofed entry must count)", total)
	}
	if running != 0 {
		t.Errorf("running = %d, want 0", running)
	}
	if len(failed) != 1 || failed[0].Label != "com.apple.zzclaudetest" {
		t.Errorf("failed = %+v, want [com.apple.zzclaudetest]", failed)
	}
}

// TestParseLaunchctlList_GenuineAppleFailureStillSuppressed proves the fix
// does not regress the common case: a "com.apple." failure whose plist is
// genuinely present under a system launchd directory stays suppressed noise.
func TestParseLaunchctlList_GenuineAppleFailureStillSuppressed(t *testing.T) {
	withDarwinFixtureSource(t, func(b *source.Bundle) {
		b.PutStat("/System/Library/LaunchAgents/com.apple.realdaemon.plist", source.FileMeta{Size: 1234})
	})

	out := "PID\tStatus\tLabel\n" +
		"-\t1\tcom.apple.realdaemon\n"
	total, running, failed := parseLaunchctlList(out)

	if total != 0 {
		t.Errorf("total = %d, want 0 (genuine Apple failure stays suppressed)", total)
	}
	if len(failed) != 0 {
		t.Errorf("failed = %+v, want none", failed)
	}
	_ = running
}
