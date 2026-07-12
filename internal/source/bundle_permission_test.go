package source

import (
	"io/fs"
	"os"
	"testing"
)

// TestPutLinkPutStatPutStatfsPermission verifies that putLink/putStat/putStatfs
// preserve the "present but unreadable" identity (like putFile already does —
// see source_permission_test.go) so replay reproduces an os.IsPermission error
// instead of a generic one, and that this identity survives Save/Load.
func TestPutLinkPutStatPutStatfsPermission(t *testing.T) {
	t.Parallel()

	const (
		linkPath   = "/etc/secret-link"
		statPath   = "/etc/secret-file"
		statfsPath = "/mnt/secret-mount"
	)
	permErr := &fs.PathError{Op: "readlink", Path: linkPath, Err: fs.ErrPermission}

	b := NewBundle()
	b.putLink(linkPath, "", permErr)
	b.putStat(statPath, FileMeta{}, &fs.PathError{Op: "stat", Path: statPath, Err: fs.ErrPermission})
	b.putStatfs(statfsPath, StatfsInfo{}, &fs.PathError{Op: "statfs", Path: statfsPath, Err: fs.ErrPermission})

	check := func(label string, rp *Replay) {
		t.Helper()
		if _, err := rp.Readlink(linkPath); !os.IsPermission(err) {
			t.Errorf("%s: Readlink should replay as permission error, got %v", label, err)
		}
		if _, err := rp.Stat(statPath); !os.IsPermission(err) {
			t.Errorf("%s: Stat should replay as permission error, got %v", label, err)
		}
		if _, err := rp.Statfs(statfsPath); !os.IsPermission(err) {
			t.Errorf("%s: Statfs should replay as permission error, got %v", label, err)
		}
	}

	check("in-memory", NewReplay(b))

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

// TestPutLinkPutStatPutStatfsGenericError verifies the default (neither
// not-exist nor permission) branch of putLink/putStat/putStatfs records the
// error text and replays it as a plain error, mirroring putFile's default case.
func TestPutLinkPutStatPutStatfsGenericError(t *testing.T) {
	t.Parallel()

	genericErr := os.ErrClosed // any error that is neither ErrNotExist nor ErrPermission

	b := NewBundle()
	b.putFile("/dev/weird-file", nil, genericErr)
	b.putLink("/dev/weird-link", "", genericErr)
	b.putStat("/dev/weird-stat", FileMeta{}, genericErr)
	b.putStatfs("/dev/weird-statfs", StatfsInfo{}, genericErr)

	rp := NewReplay(b)
	if _, err := rp.ReadFile("/dev/weird-file"); err == nil || os.IsNotExist(err) || os.IsPermission(err) {
		t.Errorf("ReadFile generic error replay = %v, want plain non-not-exist non-permission error", err)
	}
	if _, err := rp.Readlink("/dev/weird-link"); err == nil || os.IsNotExist(err) || os.IsPermission(err) {
		t.Errorf("Readlink generic error replay = %v, want plain non-not-exist non-permission error", err)
	}
	if _, err := rp.Stat("/dev/weird-stat"); err == nil || os.IsNotExist(err) || os.IsPermission(err) {
		t.Errorf("Stat generic error replay = %v, want plain non-not-exist non-permission error", err)
	}
	if _, err := rp.Statfs("/dev/weird-statfs"); err == nil || os.IsNotExist(err) || os.IsPermission(err) {
		t.Errorf("Statfs generic error replay = %v, want plain non-not-exist non-permission error", err)
	}
}

// TestReplayCachedGenericError verifies Replay.Cached surfaces a recorded
// produce() failure (a Cached() call that errored during capture) as a plain
// error on replay, without ever invoking produce.
func TestReplayCachedGenericError(t *testing.T) {
	t.Parallel()

	genericErr := os.ErrClosed
	b := NewBundle()
	b.putFile(cacheKey("flaky-probe"), nil, genericErr)

	produceCalled := false
	produce := func() ([]byte, error) {
		produceCalled = true
		return nil, nil
	}

	rp := NewReplay(b)
	if _, err := rp.Cached("flaky-probe", produce); err == nil {
		t.Error("Cached should replay the recorded produce() failure as an error")
	}
	if produceCalled {
		t.Error("Replay.Cached must never invoke produce")
	}
}
