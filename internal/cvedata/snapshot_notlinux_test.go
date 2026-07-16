//go:build !linux

package cvedata

import (
	"testing"
)

// TestDetectDistroID_ReturnsEmptyOnMissingFile exercises the error-return
// branch (snapshot.go:19-21) of DetectDistroID. On non-Linux platforms
// /etc/os-release is absent, so os.ReadFile returns an error and the
// function must return "".
func TestDetectDistroID_ReturnsEmptyOnMissingFile(t *testing.T) {
	t.Parallel()
	if got := DetectDistroID(); got != "" {
		t.Errorf("DetectDistroID() = %q, want \"\" on a platform without /etc/os-release", got)
	}
}
