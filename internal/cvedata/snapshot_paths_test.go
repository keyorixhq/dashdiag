package cvedata

import (
	"os"
	"path/filepath"
	"testing"
)

// ── parseDistroID (pure parsing seam extracted from DetectDistroID) ─────────

func TestParseDistroID(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name    string
		content string
		want    string
	}{
		{"ubuntu", "NAME=\"Ubuntu\"\nID=ubuntu\nVERSION_ID=\"24.04\"\n", "ubuntu"},
		{"quoted", "ID=\"rhel\"\n", "rhel"},
		{"no id field", "NAME=\"Foo\"\nVERSION=\"1\"\n", ""},
		{"empty", "", ""},
		{"id not first line", "PRETTY_NAME=\"x\"\nID=fedora\nHOME_URL=\"y\"\n", "fedora"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			t.Parallel()
			if got := parseDistroID(c.content); got != c.want {
				t.Errorf("parseDistroID(%q) = %q, want %q", c.content, got, c.want)
			}
		})
	}
}

// TestDetectDistroID_MissingFile exercises the real-filesystem wrapper's
// error path deterministically: no test can write to /etc/os-release, but we
// CAN assert the function never panics and degrades to "" when the read
// fails. On a real Linux host /etc/os-release exists, so this only proves
// the function is safe to call; parseDistroID above covers the parsing logic.
func TestDetectDistroID_DoesNotPanic(t *testing.T) {
	t.Parallel()
	_ = DetectDistroID() // must not panic on any platform
}

// ── StandardOVALPaths / FindOVALFile ─────────────────────────────────────────

func TestStandardOVALPaths(t *testing.T) {
	// no t.Parallel(): t.Setenv is incompatible with parallel subtests.
	home := t.TempDir()
	t.Setenv("HOME", home)

	got := StandardOVALPaths()
	want := []string{
		"/var/lib/dsd/oval",
		"/etc/dsd/oval",
		filepath.Join(home, ".local", "share", "dsd", "oval"),
		filepath.Join(home, ".dsd", "oval"),
	}
	if len(got) != len(want) {
		t.Fatalf("StandardOVALPaths() = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("StandardOVALPaths()[%d] = %q, want %q", i, got[i], want[i])
		}
	}
}

func TestFindOVALFile_CandidateName(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)

	dir := filepath.Join(home, ".dsd", "oval")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "fedora.xml.bz2")
	if err := os.WriteFile(path, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}

	got := FindOVALFile("Fedora 40")
	if got != path {
		t.Errorf("FindOVALFile(Fedora) = %q, want %q", got, path)
	}
}

func TestFindOVALFile_GenericXMLFallback(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)

	dir := filepath.Join(home, ".local", "share", "dsd", "oval")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	// Distro yields no named candidates, but any .xml/.xml.bz2 in the dir
	// is accepted as a fallback.
	path := filepath.Join(dir, "custom-feed.xml")
	if err := os.WriteFile(path, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}

	got := FindOVALFile("SomeUnknownDistro")
	if got != path {
		t.Errorf("FindOVALFile(unknown) = %q, want %q (generic .xml fallback)", got, path)
	}
}

func TestFindOVALFile_NotFound(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)

	if got := FindOVALFile("rhel 9"); got != "" {
		t.Errorf("FindOVALFile() = %q, want \"\"", got)
	}
}

// ── SnapshotStandardPaths / FindSnapshot ─────────────────────────────────────

func TestSnapshotStandardPaths(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)

	got := SnapshotStandardPaths()
	want := []string{
		"/var/lib/dsd/cvedata.json.gz",
		"/var/lib/dsd/cvedata.json",
		"/etc/dsd/cvedata.json.gz",
		filepath.Join(home, ".local", "share", "dsd", "cvedata.json.gz"),
		filepath.Join(home, ".dsd", "cvedata.json.gz"),
	}
	if len(got) != len(want) {
		t.Fatalf("SnapshotStandardPaths() = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("SnapshotStandardPaths()[%d] = %q, want %q", i, got[i], want[i])
		}
	}
}

func TestFindSnapshot_Found(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)

	dir := filepath.Join(home, ".dsd")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "cvedata.json.gz")
	if err := os.WriteFile(path, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}

	got := FindSnapshot()
	if got != path {
		t.Errorf("FindSnapshot() = %q, want %q", got, path)
	}
}

func TestFindSnapshot_NotFound(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)

	if got := FindSnapshot(); got != "" {
		t.Errorf("FindSnapshot() = %q, want \"\"", got)
	}
}
