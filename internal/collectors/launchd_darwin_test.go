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
`

func TestParseLaunchctlList(t *testing.T) {
	total, running, failed := parseLaunchctlList(launchctlOutput)

	// apple.security prefix is noise — filtered out
	// Remaining: Spotlight (running), screensaver (idle ok), myapp (failed 1),
	//            crasher (failed 127), mySQLd (running)
	if total != 5 {
		t.Errorf("total = %d, want 5 (apple.security filtered)", total)
	}
	if running != 2 {
		t.Errorf("running = %d, want 2 (Spotlight + mySQLd)", running)
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
	noisy := []string{
		"com.apple.security.keychain-circle-notification",
		"com.apple.xpc.launchd.oneshot",
		"com.apple.system.logger",
	}
	signal := []string{
		"com.example.myapp",
		"com.homebrew.postgresql",
		"org.nginx.nginx",
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
