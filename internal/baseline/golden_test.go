package baseline

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// SaveGolden / LoadGolden round-trip: a named golden baseline is written under
// $HOME/.dsd/golden/<name>.json and reloads to an equal snapshot.
func TestGolden_SaveLoadRoundTrip(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("HOME", dir)

	snap := &Snapshot{
		Hostname:  "goldhost",
		Version:   "v9.9.9",
		Timestamp: time.Now().UTC().Truncate(time.Second),
		Checks:    []CheckResult{{Name: "cpu", Status: "OK", Value: "5%"}},
	}
	if err := SaveGolden(snap, "prod"); err != nil {
		t.Fatalf("SaveGolden: %v", err)
	}

	want := filepath.Join(dir, ".dsd", "golden", "prod.json")
	if _, err := os.Stat(want); err != nil {
		t.Fatalf("golden file not at %s: %v", want, err)
	}

	loaded, err := LoadGolden("prod")
	if err != nil {
		t.Fatalf("LoadGolden: %v", err)
	}
	if loaded.Version != snap.Version || loaded.Hostname != snap.Hostname {
		t.Errorf("round-trip mismatch: got %+v", loaded)
	}
	if len(loaded.Checks) != 1 || loaded.Checks[0].Name != "cpu" {
		t.Errorf("checks mismatch: got %+v", loaded.Checks)
	}
}

// TestGolden_NameTraversalSanitized is the regression guard for a path-
// traversal write/read: `dsd baseline save/diff <name>` only cobra-validates
// the argument COUNT (ExactArgs(1)), never the content, so name previously
// flowed straight into filepath.Join(goldenDir(), name+".json") unsanitized.
// A name of "../../../../tmp/evil" could write (SaveGolden) or read
// (LoadGolden) outside ~/.dsd/golden — SaveGolden.os.WriteFile truncates, and
// LoadGolden would return an arbitrary file's content as if it were a golden
// Snapshot (it happens to fail JSON parsing here, but the read itself already
// succeeded, which is the point being guarded).
func TestGolden_NameTraversalSanitized(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("HOME", dir)

	snap := &Snapshot{Hostname: "h", Version: "v1", Timestamp: time.Now().UTC().Truncate(time.Second)}
	maliciousName := "../../../../../../../../tmp/evil"

	if err := SaveGolden(snap, maliciousName); err != nil {
		t.Fatalf("SaveGolden: %v", err)
	}

	// The file must land inside ~/.dsd/golden, under the sanitized name — a
	// slash surviving anywhere in the on-disk filename means sanitization was
	// bypassed.
	gdir := filepath.Join(dir, ".dsd", "golden")
	entries, err := os.ReadDir(gdir)
	if err != nil {
		t.Fatalf("ReadDir golden dir: %v", err)
	}
	if len(entries) != 1 {
		t.Fatalf("want exactly 1 file in the golden dir, got %d: %+v", len(entries), entries)
	}
	if strings.ContainsAny(entries[0].Name(), `/\`) {
		t.Errorf("on-disk filename %q still contains a path separator — traversal not blocked", entries[0].Name())
	}

	// No file must exist anywhere outside the golden dir as a result of this save.
	if _, err := os.Stat(filepath.Join(dir, "tmp", "evil.json")); err == nil {
		t.Error("SaveGolden wrote outside ~/.dsd/golden — traversal escaped")
	}

	// LoadGolden with the same malicious name must read back the sanitized
	// file (round-trips successfully), never anything outside the golden dir.
	loaded, err := LoadGolden(maliciousName)
	if err != nil {
		t.Fatalf("LoadGolden(%q): %v", maliciousName, err)
	}
	if loaded.Hostname != "h" {
		t.Errorf("round-trip mismatch: got %+v", loaded)
	}
}

// LoadGolden on a missing name returns a helpful error, not a zero snapshot.
func TestLoadGolden_Missing(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("HOME", dir)

	if _, err := LoadGolden("nope"); err == nil {
		t.Error("LoadGolden on missing baseline should error")
	}
}

// LoadGolden on corrupt JSON surfaces a parse error.
func TestLoadGolden_Corrupt(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("HOME", dir)

	gdir := filepath.Join(dir, ".dsd", "golden")
	if err := os.MkdirAll(gdir, 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(gdir, "bad.json"), []byte("{not json"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadGolden("bad"); err == nil {
		t.Error("LoadGolden on corrupt JSON should error")
	}
}

// ListGolden returns the base names of all *.json golden files, skipping
// directories and non-json entries.
func TestListGolden(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("HOME", dir)

	// No golden dir yet → empty, no error.
	names, err := ListGolden()
	if err != nil {
		t.Fatalf("ListGolden (no dir): %v", err)
	}
	if len(names) != 0 {
		t.Errorf("expected no names before any save, got %v", names)
	}

	snap := &Snapshot{Hostname: "h", Version: "v1", Timestamp: time.Now()}
	if err := SaveGolden(snap, "alpha"); err != nil {
		t.Fatal(err)
	}
	if err := SaveGolden(snap, "beta"); err != nil {
		t.Fatal(err)
	}
	// A stray non-json file and a subdir must be ignored.
	gdir := filepath.Join(dir, ".dsd", "golden")
	if err := os.WriteFile(filepath.Join(gdir, "notes.txt"), []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(gdir, "subdir.json"), 0o750); err != nil {
		t.Fatal(err)
	}

	names, err = ListGolden()
	if err != nil {
		t.Fatalf("ListGolden: %v", err)
	}
	got := map[string]bool{}
	for _, n := range names {
		got[n] = true
	}
	if !got["alpha"] || !got["beta"] {
		t.Errorf("expected alpha and beta, got %v", names)
	}
	if got["notes"] || got["subdir"] {
		t.Errorf("non-json / dir entries must be skipped, got %v", names)
	}
}
