//go:build linux

package collectors

import (
	"io/fs"
	"testing"
	"time"

	"github.com/keyorixhq/dashdiag/internal/source"
)

// TestFakeDirEntry covers fakeDirEntry's fs.DirEntry surface: Type() is always 0
// (unknown — readDirEntries has no mode bits to report), and Info() hands back a
// fakeFileInfo carrying the same name/isDir.
func TestFakeDirEntry(t *testing.T) {
	e := fakeDirEntry{name: "sda", isDir: true}
	if e.Type() != fs.FileMode(0) {
		t.Errorf("Type() = %v, want 0", e.Type())
	}
	info, err := e.Info()
	if err != nil {
		t.Fatalf("Info() error: %v", err)
	}
	if info.Name() != "sda" || !info.IsDir() {
		t.Errorf("Info() = %+v, want Name=sda IsDir=true", info)
	}
}

// TestFakeFileInfo covers fakeFileInfo's fs.FileInfo surface. readDirEntries has
// no real size/mode/mtime to report (the source only exposes names), so these
// are fixed placeholder values by design — not real filesystem metadata.
func TestFakeFileInfo(t *testing.T) {
	fi := fakeFileInfo{name: "eth0", isDir: false}
	if fi.Name() != "eth0" {
		t.Errorf("Name() = %q, want eth0", fi.Name())
	}
	if fi.Size() != 0 {
		t.Errorf("Size() = %d, want 0 (unknown — not tracked by the fake)", fi.Size())
	}
	if fi.Mode() != fs.FileMode(0o644) {
		t.Errorf("Mode() = %v, want 0644", fi.Mode())
	}
	if !fi.ModTime().Equal(time.Time{}) {
		t.Errorf("ModTime() = %v, want the zero time", fi.ModTime())
	}
	if fi.IsDir() {
		t.Error("IsDir() = true, want false")
	}
	if fi.Sys() != nil {
		t.Errorf("Sys() = %v, want nil", fi.Sys())
	}

	dirFI := fakeFileInfo{name: "mc0", isDir: true}
	if !dirFI.IsDir() {
		t.Error("IsDir() = false, want true for a directory entry")
	}
}

func TestReadFileViaSource(t *testing.T) {
	withFixtureSource(t, func(b *source.Bundle) {
		b.PutFile("/etc/hostname", []byte("host1\n"))
	})
	data, err := ReadFileViaSource("/etc/hostname")
	if err != nil {
		t.Fatalf("ReadFileViaSource error: %v", err)
	}
	if string(data) != "host1\n" {
		t.Errorf("ReadFileViaSource = %q, want %q", data, "host1\n")
	}
}

func TestReadFileViaSource_Missing(t *testing.T) {
	withFixtureSource(t, func(b *source.Bundle) {})
	if _, err := ReadFileViaSource("/etc/nope"); err == nil {
		t.Error("ReadFileViaSource error = nil, want an error for an unseeded path")
	}
}

func TestGlobViaSource(t *testing.T) {
	withFixtureSource(t, func(b *source.Bundle) {
		b.PutGlob("/sys/class/net/*/address", []string{"/sys/class/net/eth0/address"})
	})
	matches, err := GlobViaSource("/sys/class/net/*/address")
	if err != nil {
		t.Fatalf("GlobViaSource error: %v", err)
	}
	if len(matches) != 1 || matches[0] != "/sys/class/net/eth0/address" {
		t.Errorf("GlobViaSource = %v, want [/sys/class/net/eth0/address]", matches)
	}
}

func TestGlobViaSource_NoMatches(t *testing.T) {
	withFixtureSource(t, func(b *source.Bundle) {})
	if _, err := GlobViaSource("/sys/class/net/*/address"); err == nil {
		t.Error("GlobViaSource error = nil, want an error for an unseeded pattern")
	}
}
