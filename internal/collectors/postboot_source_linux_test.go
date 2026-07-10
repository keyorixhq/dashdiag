//go:build linux

package collectors

import (
	"context"
	"io/fs"
	"os"
	"path/filepath"
	"testing"
)

// pbDirEntry is a minimal os.DirEntry for driving pbDirHasJournal off fixtures without
// touching the real /var/log/journal.
type pbDirEntry struct {
	name string
	dir  bool
}

func (e pbDirEntry) Name() string { return e.name }
func (e pbDirEntry) IsDir() bool  { return e.dir }
func (e pbDirEntry) Type() fs.FileMode {
	if e.dir {
		return fs.ModeDir
	}
	return 0
}
func (e pbDirEntry) Info() (fs.FileInfo, error) { return nil, nil }

// journalReadDir fakes a populated /var/log/journal: one machine subdir holding a
// .journal file, so pbDirHasJournal reports persistent journald.
func journalReadDir(path string) ([]os.DirEntry, error) {
	switch path {
	case persistentJournalDir:
		return []os.DirEntry{pbDirEntry{name: "machine-abc", dir: true}}, nil
	case filepath.Join(persistentJournalDir, "machine-abc"):
		return []os.DirEntry{pbDirEntry{name: "system.journal", dir: false}}, nil
	}
	return nil, os.ErrNotExist
}

// noJournalReadDir fakes an absent/empty /var/log/journal (volatile journald).
func noJournalReadDir(string) ([]os.DirEntry, error) { return nil, os.ErrNotExist }

func priorBoots(n int) func(context.Context) (int, error) {
	return func(context.Context) (int, error) { return n, nil }
}

func TestAssessPostBootSource_Trichotomy(t *testing.T) {
	ctx := context.Background()

	t.Run("non-systemd with wtmp → Found/wtmp (coarse)", func(t *testing.T) {
		r := assessPostBootSource(ctx, pbEnv{isSystemd: false, hasWtmp: true, readDir: noJournalReadDir})
		if r.State != PBStateFound || r.Primary != PBSourceWtmp {
			t.Errorf("got %+v, want Found/wtmp", r)
		}
	})

	t.Run("non-systemd no wtmp → Unmeasurable (blind)", func(t *testing.T) {
		r := assessPostBootSource(ctx, pbEnv{isSystemd: false, hasWtmp: false, readDir: noJournalReadDir})
		if r.State != PBStateUnmeasurable || r.Reason != PBReasonNonSystemdNoWtmp {
			t.Errorf("got %+v, want Unmeasurable/non_systemd_no_wtmp", r)
		}
	})

	t.Run("systemd, volatile journal, wtmp → downgraded Found/wtmp", func(t *testing.T) {
		r := assessPostBootSource(ctx, pbEnv{isSystemd: true, hasWtmp: true, readDir: noJournalReadDir})
		if r.State != PBStateFound || r.Primary != PBSourceWtmp || r.Reason != PBReasonNoPersistentJournal {
			t.Errorf("got %+v, want Found/wtmp with no_persistent_journal advisory", r)
		}
	})

	t.Run("systemd, volatile journal, no wtmp → Unmeasurable", func(t *testing.T) {
		r := assessPostBootSource(ctx, pbEnv{isSystemd: true, hasWtmp: false, readDir: noJournalReadDir})
		if r.State != PBStateUnmeasurable || r.Reason != PBReasonNoPersistentJournal {
			t.Errorf("got %+v, want Unmeasurable/no_persistent_journal", r)
		}
	})

	t.Run("systemd, journal present, EACCES → Unmeasurable/unreadable", func(t *testing.T) {
		r := assessPostBootSource(ctx, pbEnv{
			isSystemd: true, hasWtmp: true, readDir: journalReadDir,
			countPriorBoots: func(context.Context) (int, error) { return 0, os.ErrPermission },
		})
		if r.State != PBStateUnmeasurable || r.Reason != PBReasonJournalUnreadable {
			t.Errorf("got %+v, want Unmeasurable/journal_unreadable", r)
		}
	})

	t.Run("systemd, journal present, 0 prior boots → Absent/first_boot", func(t *testing.T) {
		r := assessPostBootSource(ctx, pbEnv{
			isSystemd: true, hasWtmp: false, readDir: journalReadDir,
			countPriorBoots: priorBoots(0),
		})
		if r.State != PBStateAbsent || r.Reason != PBReasonFirstBoot {
			t.Errorf("got %+v, want Absent/first_boot", r)
		}
	})

	t.Run("systemd, journal present, N prior boots → Found/persistent_journal", func(t *testing.T) {
		r := assessPostBootSource(ctx, pbEnv{
			isSystemd: true, hasWtmp: true, readDir: journalReadDir,
			countPriorBoots: priorBoots(3),
		})
		if r.State != PBStateFound || r.Primary != PBSourcePersistentJournal || r.PriorBoots != 3 {
			t.Errorf("got %+v, want Found/persistent_journal with 3 prior boots", r)
		}
		// wtmp is available as a corroborating fallback — but never the kernel ring buffer.
		if len(r.Fallbacks) != 1 || r.Fallbacks[0] != PBSourceWtmp {
			t.Errorf("fallbacks = %v, want [wtmp]", r.Fallbacks)
		}
	})
}

func TestPBDirHasJournal(t *testing.T) {
	if !pbDirHasJournal(pbEnv{readDir: journalReadDir}, persistentJournalDir) {
		t.Error("a machine subdir with a .journal file must read as persistent")
	}
	if pbDirHasJournal(pbEnv{readDir: noJournalReadDir}, persistentJournalDir) {
		t.Error("an absent journal dir must read as volatile (not persistent)")
	}
	// A journal dir that exists but holds no .journal file (created, never rotated) is
	// NOT persistent evidence.
	emptyMachine := func(path string) ([]os.DirEntry, error) {
		if path == persistentJournalDir {
			return []os.DirEntry{pbDirEntry{name: "machine-abc", dir: true}}, nil
		}
		return nil, nil // machine subdir is empty
	}
	if pbDirHasJournal(pbEnv{readDir: emptyMachine}, persistentJournalDir) {
		t.Error("an empty machine subdir (no .journal) must NOT read as persistent")
	}
}

// TestPBDirHasJournal_SkipsNonDirEntries guards the `!e.IsDir()` continue: a
// stray non-directory file directly under /var/log/journal (e.g. a README or
// remote-XXXX.journal placed at the top level rather than in a machine-id
// subdir) must be skipped without attempting to readDir() it as if it were a
// subdirectory.
func TestPBDirHasJournal_SkipsNonDirEntries(t *testing.T) {
	readDir := func(path string) ([]os.DirEntry, error) {
		switch path {
		case persistentJournalDir:
			return []os.DirEntry{
				pbDirEntry{name: "README", dir: false}, // must be skipped, not descended into
				pbDirEntry{name: "machine-abc", dir: true},
			}, nil
		case filepath.Join(persistentJournalDir, "machine-abc"):
			return []os.DirEntry{pbDirEntry{name: "system.journal", dir: false}}, nil
		}
		return nil, os.ErrNotExist
	}
	if !pbDirHasJournal(pbEnv{readDir: readDir}, persistentJournalDir) {
		t.Error("a non-dir top-level entry must be skipped, and the real machine subdir still found")
	}
}

// TestPBDirHasJournal_InnerReadDirErrorContinues guards the inner readDir
// error path: one machine subdir that can't be read (e.g. permission denied)
// must not abort the whole scan — a LATER subdir with a real .journal file
// must still be found.
func TestPBDirHasJournal_InnerReadDirErrorContinues(t *testing.T) {
	readDir := func(path string) ([]os.DirEntry, error) {
		switch path {
		case persistentJournalDir:
			return []os.DirEntry{
				pbDirEntry{name: "unreadable-machine", dir: true},
				pbDirEntry{name: "machine-abc", dir: true},
			}, nil
		case filepath.Join(persistentJournalDir, "unreadable-machine"):
			return nil, os.ErrPermission
		case filepath.Join(persistentJournalDir, "machine-abc"):
			return []os.DirEntry{pbDirEntry{name: "system.journal", dir: false}}, nil
		}
		return nil, os.ErrNotExist
	}
	if !pbDirHasJournal(pbEnv{readDir: readDir}, persistentJournalDir) {
		t.Error("an unreadable machine subdir must be skipped, and a later readable subdir with a .journal file still found")
	}
}
