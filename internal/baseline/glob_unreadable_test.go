//go:build unix

package baseline

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// unreadableBaselineDir builds $HOME/.dsd/baselines and makes it unlistable.
func unreadableBaselineDir(t *testing.T) {
	t.Helper()
	if os.Geteuid() == 0 {
		t.Skip("root bypasses directory permissions")
	}
	home := t.TempDir()
	t.Setenv("HOME", home)
	dir := filepath.Join(home, ".dsd", "baselines")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(dir, 0); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(dir, 0o700) })
}

// An unreadable baseline dir is "could not read", not "no history yet".
func TestLoadHistory_UnreadableDirIsAnError(t *testing.T) {
	unreadableBaselineDir(t)
	snaps, err := LoadHistory(5)
	if err == nil || !strings.Contains(err.Error(), "could not read baseline dir") {
		t.Fatalf("LoadHistory = (%v, %v), want a 'could not read baseline dir' error", snaps, err)
	}
}

func TestFindBaselineBeforeTime_UnreadableDirIsAnError(t *testing.T) {
	unreadableBaselineDir(t)
	_, err := FindBaselineBeforeTime(time.Now(), "host")
	if err == nil || !strings.Contains(err.Error(), "could not read baseline dir") {
		t.Fatalf("err = %v, want a 'could not read baseline dir' error", err)
	}
}
