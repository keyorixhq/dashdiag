package source

import (
	"errors"
	"io/fs"
	"os"
	"testing"
)

// failingDirSource returns err from ReadDir; every other method is unused.
type failingDirSource struct {
	Source
	err error
}

func (f failingDirSource) ReadDir(string) ([]string, error) { return nil, f.err }

// TestRecorderReadDirRecordsFailures: a capture-time ReadDir failure must replay
// as that failure (permission -> unreadable, missing -> absent, other -> error),
// never as ErrNotRecorded, so an offline replay of a root-only directory cannot
// read as "not captured / absent". Like Stat and Statfs, it survives Save/Load.
func TestRecorderReadDirRecordsFailures(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name  string
		err   error
		check func(error) bool
	}{
		{"permission", &fs.PathError{Op: "open", Path: "/d", Err: fs.ErrPermission}, os.IsPermission},
		{"not exist", &fs.PathError{Op: "open", Path: "/d", Err: fs.ErrNotExist}, os.IsNotExist},
		{"other", errors.New("input/output error"), func(err error) bool {
			return err != nil && !os.IsPermission(err) && !os.IsNotExist(err) && !errors.Is(err, ErrNotRecorded)
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			rec := NewRecorder(failingDirSource{err: tc.err})
			if _, err := rec.ReadDir("/d"); err == nil {
				t.Fatal("recorder must forward the inner error")
			}

			if _, err := NewReplay(rec.Bundle()).ReadDir("/d"); !tc.check(err) {
				t.Errorf("in-memory replay = %v", err)
			}

			out := t.TempDir()
			if err := rec.Bundle().Save(out); err != nil {
				t.Fatalf("save: %v", err)
			}
			b2, err := Load(out)
			if err != nil {
				t.Fatalf("load: %v", err)
			}
			if _, err := NewReplay(b2).ReadDir("/d"); !tc.check(err) {
				t.Errorf("replay after Save/Load = %v", err)
			}
		})
	}
}

// TestBundleDirSuccessSupersedesRecordedFailure: the last write for a path wins.
func TestBundleDirSuccessSupersedesRecordedFailure(t *testing.T) {
	t.Parallel()
	b := NewBundle()
	b.putDirErr("/d", &fs.PathError{Op: "open", Path: "/d", Err: fs.ErrPermission})
	b.PutDir("/d", []string{"a"})
	names, err := NewReplay(b).ReadDir("/d")
	if err != nil || len(names) != 1 {
		t.Fatalf("ReadDir = %v, %v; want [a], nil", names, err)
	}
}
