//go:build linux

package collectors

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/keyorixhq/dashdiag/internal/models"
)

// TestWalkSUIDDir_RecursesAndDetectsSetuid is a regression guard for the switch
// from raw filepath.Walk (with fi.Sys().(*syscall.Stat_t)) to the Source-routed
// walkSUIDDir, which reads the setuid bit via the portable statFile().Mode
// (os.ModeSetuid) instead. Recursion into subdirectories must also still work.
func TestWalkSUIDDir_RecursesAndDetectsSetuid(t *testing.T) {
	root := t.TempDir()
	sub := filepath.Join(root, "nested")
	if err := os.MkdirAll(sub, 0o755); err != nil {
		t.Fatal(err)
	}

	// os.Chmod takes a Go os.FileMode, NOT a raw Unix mode integer — os.ModeSetuid
	// is a distinct high bit from the traditional 04000 octal value, so it must
	// be OR'd in explicitly rather than passed as a literal like 0o4755.
	suidPath := filepath.Join(root, "suid-bin")
	if err := os.WriteFile(suidPath, []byte("x"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(suidPath, os.ModeSetuid|0o755); err != nil {
		t.Fatal(err)
	}

	nestedSUIDPath := filepath.Join(sub, "nested-suid-bin")
	if err := os.WriteFile(nestedSUIDPath, []byte("x"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(nestedSUIDPath, os.ModeSetuid|0o755); err != nil {
		t.Fatal(err)
	}

	normalPath := filepath.Join(root, "normal-bin")
	if err := os.WriteFile(normalPath, []byte("x"), 0o755); err != nil {
		t.Fatal(err)
	}

	var info models.SecurityInfo
	walkSUIDDir(root, &info)

	want := map[string]bool{suidPath: true, nestedSUIDPath: true}
	if len(info.SUIDBinaries) != len(want) {
		t.Fatalf("SUIDBinaries = %v, want exactly %v", info.SUIDBinaries, want)
	}
	for _, p := range info.SUIDBinaries {
		if !want[p] {
			t.Errorf("unexpected SUID binary reported: %q", p)
		}
	}
}

// TestWalkSUIDDir_KnownBinaryExcluded confirms a path in knownSUIDBinaries is
// never reported even when it genuinely carries the setuid bit.
func TestWalkSUIDDir_KnownBinaryExcluded(t *testing.T) {
	root := t.TempDir()
	knownPath := filepath.Join(root, "known-suid")
	if err := os.WriteFile(knownPath, []byte("x"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(knownPath, os.ModeSetuid|0o755); err != nil {
		t.Fatal(err)
	}
	knownSUIDBinaries[knownPath] = true
	defer delete(knownSUIDBinaries, knownPath)

	var info models.SecurityInfo
	walkSUIDDir(root, &info)
	if len(info.SUIDBinaries) != 0 {
		t.Errorf("known SUID binary must be excluded, got %v", info.SUIDBinaries)
	}
}
