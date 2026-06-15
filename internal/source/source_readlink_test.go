package source

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

// TestReadlinkRecordReplay verifies symlink reads are captured and replayed from
// the bundle rather than falling through to the replaying machine's filesystem
// (the os.Readlink-bypass bug: replay must reproduce the captured target/error).
func TestReadlinkRecordReplay(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "driver-vmxnet3")
	link := filepath.Join(dir, "device-driver")
	if err := os.Symlink(target, link); err != nil {
		t.Fatalf("symlink: %v", err)
	}
	missing := filepath.Join(dir, "no-such-link")

	rec := NewRecorder(Live{})
	if got, err := rec.Readlink(link); err != nil || got != target {
		t.Fatalf("record readlink = %q, %v; want %q", got, err, target)
	}
	if _, err := rec.Readlink(missing); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("record readlink missing should be ErrNotExist, got %v", err)
	}

	verify := func(label string, rp *Replay) {
		if got, err := rp.Readlink(link); err != nil || got != target {
			t.Fatalf("%s: replay readlink = %q, %v; want %q", label, got, err, target)
		}
		if _, err := rp.Readlink(missing); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("%s: replay missing should be ErrNotExist, got %v", label, err)
		}
		if _, err := rp.Readlink(filepath.Join(dir, "never-touched")); !errors.Is(err, ErrNotRecorded) {
			t.Fatalf("%s: unrecorded readlink should be ErrNotRecorded, got %v", label, err)
		}
	}

	verify("in-memory", NewReplay(rec.Bundle()))

	out := t.TempDir()
	if err := rec.Bundle().Save(out); err != nil {
		t.Fatalf("save: %v", err)
	}
	b2, err := Load(out)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	verify("after Save/Load", NewReplay(b2))
}
