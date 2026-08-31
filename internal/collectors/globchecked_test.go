package collectors

import (
	"errors"
	"fmt"
	"os"
	"testing"

	"github.com/keyorixhq/dashdiag/internal/source"
)

// globCheckedFixtureSource gives full, direct control over Glob and ReadDir's
// return values — the two calls globChecked composes — without depending on
// a real filesystem or the Bundle/Replay recording format (globChecked's
// directory-readability fallback is a live-only concept, same reasoning as
// C2's kmsg open-error signal).
type globCheckedFixtureSource struct {
	*source.Replay
	globMatches []string
	globErr     error
	readDirErr  error
}

func (f globCheckedFixtureSource) Glob(string) ([]string, error) { return f.globMatches, f.globErr }
func (f globCheckedFixtureSource) ReadDir(string) ([]string, error) {
	if f.readDirErr != nil {
		return nil, f.readDirErr
	}
	return nil, nil
}

// TestGlobChecked_EmptyReadableDirIsNotUnreadable is the positive control:
// a directory that is genuinely empty (or has no matching files) and CAN be
// read must not be flagged unreadable — globChecked must not manufacture a
// false caveat on the ordinary "nothing here" case.
func TestGlobChecked_EmptyReadableDirIsNotUnreadable(t *testing.T) {
	prev := SetSource(globCheckedFixtureSource{Replay: source.NewReplay(source.NewBundle())})
	t.Cleanup(func() { SetSource(prev) })

	matches, unreadable, err := globChecked("/etc/systemd/network/*.network")
	if err != nil || unreadable || matches != nil {
		t.Errorf("got matches=%v unreadable=%v err=%v, want (nil, false, nil)", matches, unreadable, err)
	}
}

// TestGlobChecked_NonemptyMatchesSkipsTheReadDirCheck confirms the common
// case (files ARE found) never even consults ReadDir — a nonempty Glob
// result already proves the directory was readable.
func TestGlobChecked_NonemptyMatchesSkipsTheReadDirCheck(t *testing.T) {
	prev := SetSource(globCheckedFixtureSource{
		Replay:      source.NewReplay(source.NewBundle()),
		globMatches: []string{"/etc/systemd/network/10-eth0.network"},
		// If globChecked consulted ReadDir here, this would wrongly flag
		// unreadable even though Glob just proved the directory readable.
		readDirErr: fmt.Errorf("readdir /etc/systemd/network: %w", os.ErrPermission),
	})
	t.Cleanup(func() { SetSource(prev) })

	matches, unreadable, err := globChecked("/etc/systemd/network/*.network")
	if err != nil || unreadable || len(matches) != 1 {
		t.Errorf("got matches=%v unreadable=%v err=%v, want ([1 match], false, nil)", matches, unreadable, err)
	}
}

// TestGlobChecked_PermissionDeniedDirIsUnreadable is the defect this closes:
// filepath.Glob (which glob() wraps) silently swallows a permission-denied
// error on the pattern's base directory as a nil-error EMPTY result — so a
// caller checking only len(matches)==0 cannot tell a genuinely empty,
// readable directory from one it was denied access to. This is
// NetworkdConfigCollector's actual bug: a non-world-readable
// /etc/systemd/network (some hardened images ship it 0750
// root:systemd-network) reports a clean 0/0 permission audit instead of
// "couldn't scan".
func TestGlobChecked_PermissionDeniedDirIsUnreadable(t *testing.T) {
	prev := SetSource(globCheckedFixtureSource{
		Replay:     source.NewReplay(source.NewBundle()),
		readDirErr: fmt.Errorf("readdir /etc/systemd/network: %w", os.ErrPermission),
	})
	t.Cleanup(func() { SetSource(prev) })

	matches, unreadable, err := globChecked("/etc/systemd/network/*.network")
	if err != nil {
		t.Errorf("got err=%v, want nil (a directory-read permission failure is reported via the unreadable bool, not as an error)", err)
	}
	if matches != nil {
		t.Errorf("got matches=%v, want nil", matches)
	}
	if !unreadable {
		t.Error("expected unreadable=true when the base directory could not be read, got false")
	}
}

// TestGlobChecked_OtherReadDirErrorsAreNotFlagged confirms only a genuine
// permission error trips the unreadable bool — e.g. a directory that
// doesn't exist at all is a normal "not present" case (ENOENT), not a
// couldn't-verify case, and must not be conflated with it.
func TestGlobChecked_OtherReadDirErrorsAreNotFlagged(t *testing.T) {
	prev := SetSource(globCheckedFixtureSource{
		Replay:     source.NewReplay(source.NewBundle()),
		readDirErr: fmt.Errorf("readdir /etc/systemd/network: %w", os.ErrNotExist),
	})
	t.Cleanup(func() { SetSource(prev) })

	_, unreadable, _ := globChecked("/etc/systemd/network/*.network")
	if unreadable {
		t.Error("expected unreadable=false for a not-exist directory, got true")
	}
}

// TestGlobChecked_GlobErrorPassesThrough confirms a genuine glob error
// (ErrBadPattern — the only error filepath.Glob itself can ever return)
// still propagates as an error, unchanged from glob()'s existing contract.
func TestGlobChecked_GlobErrorPassesThrough(t *testing.T) {
	wantErr := errors.New("bad pattern")
	prev := SetSource(globCheckedFixtureSource{
		Replay:  source.NewReplay(source.NewBundle()),
		globErr: wantErr,
	})
	t.Cleanup(func() { SetSource(prev) })

	_, unreadable, err := globChecked("[")
	if !errors.Is(err, wantErr) {
		t.Errorf("got err=%v, want %v", err, wantErr)
	}
	if unreadable {
		t.Error("expected unreadable=false on a glob error (distinct failure mode)")
	}
}
