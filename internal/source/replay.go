package source

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os/exec"
)

// Replay serves reads and execs from a Bundle, re-running real collector code
// against recorded inputs. Any input that was never recorded returns
// ErrNotRecorded — Replay never falls through to the live system.
type Replay struct{ b *Bundle }

// NewReplay returns a Replay backed by b.
func NewReplay(b *Bundle) *Replay { return &Replay{b: b} }

func (rp *Replay) ReadFile(path string) ([]byte, error) {
	rec, ok := rp.b.getFile(path)
	if !ok {
		return nil, fmt.Errorf("%w: ReadFile %s", ErrNotRecorded, path)
	}
	if rec.notExist {
		// Replay absence as a real os.ErrNotExist so collector code that checks
		// os.IsNotExist / errors.Is behaves identically to the live run.
		return nil, &fs.PathError{Op: "open", Path: path, Err: fs.ErrNotExist}
	}
	if rec.permission {
		// Present but unreadable — reconstruct an os.IsPermission-satisfying error
		// so a collector's "present but not readable" branch fires as it did live.
		return nil, &fs.PathError{Op: "open", Path: path, Err: fs.ErrPermission}
	}
	if rec.errText != "" {
		return nil, errors.New(rec.errText)
	}
	return append([]byte(nil), rec.data...), nil
}

func (rp *Replay) Glob(pattern string) ([]string, error) {
	m, ok := rp.b.getGlob(pattern)
	if !ok {
		return nil, fmt.Errorf("%w: Glob %s", ErrNotRecorded, pattern)
	}
	return append([]string(nil), m...), nil
}

func (rp *Replay) ReadDir(dir string) ([]string, error) {
	n, ok := rp.b.getDir(dir)
	if !ok {
		return nil, fmt.Errorf("%w: ReadDir %s", ErrNotRecorded, dir)
	}
	return append([]string(nil), n...), nil
}

func (rp *Replay) Run(ctx context.Context, name string, args ...string) (Result, error) {
	rec, ok := rp.b.getCmd(name, args)
	if !ok {
		return Result{}, fmt.Errorf("%w: Run %s %v", ErrNotRecorded, name, args)
	}
	if rec.absent {
		// Reproduce a genuine spawn failure (e.g. tool not installed).
		return rec.res, &exec.Error{Name: name, Err: exec.ErrNotFound}
	}
	return rec.res, nil
}
