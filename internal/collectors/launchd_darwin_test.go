//go:build darwin

package collectors

import (
	"testing"
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
