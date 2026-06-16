package collectors

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/keyorixhq/dashdiag/internal/source"
)

// TestStatGatesRouteThroughSource is the guard that keeps the pilot-critical
// existence/stat gates faithful under `dsd replay`: statFile/fileExists must read
// the active source (the captured bundle), never the replaying machine's own
// filesystem. We record a real file, then DELETE it on disk before replaying — if
// the gate still sees it, the read came from the bundle, not from the live FS.
func TestStatGatesRouteThroughSource(t *testing.T) {
	dir := t.TempDir()
	present := filepath.Join(dir, "present")
	if err := os.WriteFile(present, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	missing := filepath.Join(dir, "missing")

	// Capture the live stat outcomes through a Recorder, then restore.
	rec := source.NewRecorder(source.Live{})
	prev := SetSource(rec)
	if !fileExists(present) {
		SetSource(prev)
		t.Fatal("present should exist during capture")
	}
	if fileExists(missing) {
		SetSource(prev)
		t.Fatal("missing should not exist during capture")
	}
	SetSource(prev)

	// Remove the file from disk so a live os.Stat would now report it absent.
	if err := os.Remove(present); err != nil {
		t.Fatal(err)
	}

	// Replay from the bundle. The gate must reflect capture-time truth.
	defer SetSource(SetSource(source.NewReplay(rec.Bundle())))
	if !fileExists(present) {
		t.Fatal("fileExists hit the live FS on replay (file was deleted) instead of the bundle")
	}
	if fileExists(missing) {
		t.Fatal("missing should still be absent on replay")
	}
}
