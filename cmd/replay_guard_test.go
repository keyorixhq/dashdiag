package cmd

import (
	"runtime"
	"strings"
	"testing"

	"github.com/keyorixhq/dashdiag/internal/source"
)

// The guard must refuse a bundle whose OS family differs from the replaying
// machine (cross-platform replay reports the local host's findings under the
// captured name), allow a matching one, and honour --force.
func TestReplayPlatformGuard(t *testing.T) {
	match := &source.Bundle{Manifest: source.Manifest{GOOS: runtime.GOOS, OS: "captured-host"}}
	if err := replayPlatformGuard(match, false); err != nil {
		t.Errorf("matching platform should pass, got: %v", err)
	}

	other := "linux"
	if runtime.GOOS == "linux" {
		other = "darwin"
	}
	mismatch := &source.Bundle{Manifest: source.Manifest{GOOS: other, OS: "captured-host"}}

	err := replayPlatformGuard(mismatch, false)
	if err == nil {
		t.Fatal("mismatched platform should be refused")
	}
	if !strings.Contains(err.Error(), other) || !strings.Contains(err.Error(), runtime.GOOS) {
		t.Errorf("error should name both OSes, got: %v", err)
	}

	if err := replayPlatformGuard(mismatch, true); err != nil {
		t.Errorf("--force should override the guard, got: %v", err)
	}
}
