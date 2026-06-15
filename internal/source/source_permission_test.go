package source

import (
	"io/fs"
	"os"
	"testing"
)

// TestReplayPreservesPermissionError verifies that a file recorded as
// present-but-unreadable (permission denied) replays as an os.IsPermission error,
// not as absence. Collectors branch on os.IsPermission to emit "config present but
// not readable" diagnostics; before the fix replay returned a generic errors.New
// that failed that check, so replay silently dropped those insights.
func TestReplayPreservesPermissionError(t *testing.T) {
	const path = "/etc/ssh/sshd_config"
	permErr := &fs.PathError{Op: "open", Path: path, Err: fs.ErrPermission}

	b := NewBundle()
	b.putFile(path, nil, permErr)

	check := func(label string, rp *Replay) {
		_, err := rp.ReadFile(path)
		if !os.IsPermission(err) {
			t.Fatalf("%s: replay should reproduce os.IsPermission, got %v", label, err)
		}
		if os.IsNotExist(err) {
			t.Fatalf("%s: a permission error must not replay as not-exist", label)
		}
	}

	check("in-memory", NewReplay(b))

	// The identity must survive the Save/Load bundle round-trip too.
	out := t.TempDir()
	if err := b.Save(out); err != nil {
		t.Fatalf("save: %v", err)
	}
	b2, err := Load(out)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	check("after Save/Load", NewReplay(b2))
}
