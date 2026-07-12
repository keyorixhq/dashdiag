package cvedata

import (
	"os"
	"path/filepath"
	"testing"
)

// TestKEVStandardPaths pins the system-wide-first ordering and confirms the
// home-relative candidates are appended when $HOME resolves.
func TestKEVStandardPaths(t *testing.T) {
	// no t.Parallel(): t.Setenv is incompatible with parallel subtests.
	home := t.TempDir()
	t.Setenv("HOME", home)

	got := KEVStandardPaths()
	want := []string{
		"/var/lib/dsd/kev",
		"/etc/dsd/kev",
		filepath.Join(home, ".local", "share", "dsd", "kev"),
		filepath.Join(home, ".dsd", "kev"),
	}
	if len(got) != len(want) {
		t.Fatalf("KEVStandardPaths() = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("KEVStandardPaths()[%d] = %q, want %q", i, got[i], want[i])
		}
	}
}

// TestFindKEVFile_CanonicalName exercises the canonical-filename hit inside
// the home-relative ".dsd/kev" candidate directory (system-wide paths don't
// exist in the test sandbox, so the search falls through to $HOME).
func TestFindKEVFile_CanonicalName(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)

	dir := filepath.Join(home, ".dsd", "kev")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "known_exploited_vulnerabilities.json")
	if err := os.WriteFile(path, []byte(sampleKEV), 0o600); err != nil {
		t.Fatal(err)
	}

	got := FindKEVFile()
	if got != path {
		t.Errorf("FindKEVFile() = %q, want %q", got, path)
	}
}

// TestFindKEVFile_GlobFallback exercises the "any *.json containing kev"
// fallback when the canonical filename isn't present.
func TestFindKEVFile_GlobFallback(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)

	dir := filepath.Join(home, ".local", "share", "dsd", "kev")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "cisa-kev-2026-07.json.gz")
	if err := os.WriteFile(path, []byte("not really gzip, just presence matters"), 0o600); err != nil {
		t.Fatal(err)
	}

	got := FindKEVFile()
	if got != path {
		t.Errorf("FindKEVFile() = %q, want %q (glob fallback on *kev*.json.gz)", got, path)
	}
}

// TestFindKEVFile_NotFound confirms "" is returned, never a path to a
// nonexistent file, when no standard directory has a KEV catalog.
func TestFindKEVFile_NotFound(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)

	if got := FindKEVFile(); got != "" {
		t.Errorf("FindKEVFile() = %q, want \"\" when nothing present", got)
	}
}

// TestFindKEVFile_IgnoresUnrelatedFiles confirms a directory containing only
// unrelated files (wrong extension, or no "kev"/"known_exploited" substring)
// is skipped.
func TestFindKEVFile_IgnoresUnrelatedFiles(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)

	dir := filepath.Join(home, ".dsd", "kev")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"readme.txt", "catalog.csv", "notes.json.bak"} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte("x"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if got := FindKEVFile(); got != "" {
		t.Errorf("FindKEVFile() = %q, want \"\" (no matching file)", got)
	}
}

// TestLoadKEVFromStandardPaths_Found and _NotFound cover the two documented
// outcomes: a real catalog loaded from a standard path, and the (nil, nil)
// "no catalog available" contract callers rely on.
func TestLoadKEVFromStandardPaths_Found(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)

	dir := filepath.Join(home, ".dsd", "kev")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "known_exploited_vulnerabilities.json")
	if err := os.WriteFile(path, []byte(sampleKEV), 0o600); err != nil {
		t.Fatal(err)
	}

	cat, err := LoadKEVFromStandardPaths()
	if err != nil {
		t.Fatalf("LoadKEVFromStandardPaths: %v", err)
	}
	if cat == nil || cat.Count() != 2 {
		t.Errorf("catalog = %+v, want 2 entries loaded from standard path", cat)
	}
}

func TestLoadKEVFromStandardPaths_NotFound(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)

	cat, err := LoadKEVFromStandardPaths()
	if err != nil {
		t.Errorf("expected nil error for absent catalog, got %v", err)
	}
	if cat != nil {
		t.Errorf("expected nil catalog when nothing found, got %+v", cat)
	}
}
