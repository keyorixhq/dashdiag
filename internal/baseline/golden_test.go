package baseline

import (
	"os"
	"path/filepath"
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
