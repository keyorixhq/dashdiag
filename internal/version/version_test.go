package version

import "testing"

func TestDefaults(t *testing.T) {
	t.Parallel()
	if Version == "" {
		t.Error("Version should never be empty")
	}
	if Commit == "" {
		t.Error("Commit should never be empty")
	}
	if Built == "" {
		t.Error("Built should never be empty")
	}
}
