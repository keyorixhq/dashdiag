package inventory

import (
	"os"
	"path/filepath"
	"testing"
)

// countDir counts only subdirectories (used to count e.g. installed-kernel dirs).
// Files and a missing directory must not contribute.
func TestCountDir(t *testing.T) {
	dir := t.TempDir()
	for _, d := range []string{"a", "b", "c"} {
		if err := os.Mkdir(filepath.Join(dir, d), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	for _, f := range []string{"f1", "f2"} {
		if err := os.WriteFile(filepath.Join(dir, f), []byte("x"), 0o644); err != nil {
			t.Fatal(err)
		}
	}

	if got := countDir(dir); got != 3 {
		t.Errorf("countDir = %d, want 3 (subdirs only, files excluded)", got)
	}
	if got := countDir(filepath.Join(dir, "does-not-exist")); got != 0 {
		t.Errorf("missing dir = %d, want 0", got)
	}
	if got := countDir(t.TempDir()); got != 0 {
		t.Errorf("empty dir = %d, want 0", got)
	}
}
