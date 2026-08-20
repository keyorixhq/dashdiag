package cmd

// writefile_test.go — writeFileNoFollow had no test of its own despite being
// the shared symlink-safe writer guest.go/hook.go both depend on.

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestWriteFileNoFollow_WritesNewFile(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "out.txt")
	if err := writeFileNoFollow(path, []byte("hello"), 0o644); err != nil {
		t.Fatalf("writeFileNoFollow: %v", err)
	}
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	if string(got) != "hello" {
		t.Errorf("content = %q, want %q", got, "hello")
	}
}

func TestWriteFileNoFollow_TruncatesExisting(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "out.txt")
	if err := os.WriteFile(path, []byte("old content, much longer than new"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := writeFileNoFollow(path, []byte("new"), 0o644); err != nil {
		t.Fatalf("writeFileNoFollow: %v", err)
	}
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "new" {
		t.Errorf("content = %q, want %q (truncated, not appended)", got, "new")
	}
}

func TestWriteFileNoFollow_RefusesSymlink(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	target := filepath.Join(dir, "elsewhere")
	if err := os.WriteFile(target, []byte("original"), 0o600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "link.txt")
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}

	err := writeFileNoFollow(link, []byte("attacker data"), 0o644)
	if err == nil || !strings.Contains(err.Error(), "refusing to write through a symlink") {
		t.Errorf("writeFileNoFollow(symlink) = %v, want a symlink-refusal error", err)
	}
	got, readErr := os.ReadFile(target)
	if readErr != nil {
		t.Fatal(readErr)
	}
	if string(got) != "original" {
		t.Errorf("symlink target was overwritten: %q", got)
	}
}
