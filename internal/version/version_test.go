package version

import "testing"

func TestDefaults(t *testing.T) {
	t.Parallel()
	if Version != "dev" {
		t.Errorf("Version default mismatch: expected %q, got %q", "dev", Version)
	}
	if Commit != "none" {
		t.Errorf("Commit default mismatch: expected %q, got %q", "none", Commit)
	}
	if Built != "unknown" {
		t.Errorf("Built default mismatch: expected %q, got %q", "unknown", Built)
	}
}
