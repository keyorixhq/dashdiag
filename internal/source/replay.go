package source

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os/exec"
	"sync/atomic"
)

// Replay serves reads and execs from a Bundle, re-running real collector code
// against recorded inputs. Any input that was never recorded returns
// ErrNotRecorded — Replay never falls through to the live system.
type Replay struct {
	b    *Bundle
	gaps atomic.Int64
}

// gap counts one refused input (see Gaps) and returns err unchanged.
func (rp *Replay) gap(err error) error {
	rp.gaps.Add(1)
	return err
}

// Gaps is how many reads the bundle could not serve because it never recorded
// them (ErrNotRecorded). dsd replay hands it to runner.GapCount so each
// collector's gaps are told apart from a real finding.
func (rp *Replay) Gaps() int { return int(rp.gaps.Load()) }

// NewReplay returns a Replay backed by b.
func NewReplay(b *Bundle) *Replay { return &Replay{b: b} }

func (rp *Replay) ReadFile(path string) ([]byte, error) {
	rec, ok := rp.b.getFile(path)
	if !ok {
		return nil, rp.gap(fmt.Errorf("%w: ReadFile %s", ErrNotRecorded, path))
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
		return nil, rp.gap(fmt.Errorf("%w: Glob %s", ErrNotRecorded, pattern))
	}
	return append([]string(nil), m...), nil
}

func (rp *Replay) ReadDir(dir string) ([]string, error) {
	n, ok := rp.b.getDir(dir)
	if !ok {
		if rec, bad := rp.b.getDirErr(dir); bad {
			switch {
			case rec.notExist:
				return nil, &fs.PathError{Op: "open", Path: dir, Err: fs.ErrNotExist}
			case rec.permission:
				return nil, &fs.PathError{Op: "open", Path: dir, Err: fs.ErrPermission}
			default:
				return nil, errors.New(rec.errText)
			}
		}
		return nil, rp.gap(fmt.Errorf("%w: ReadDir %s", ErrNotRecorded, dir))
	}
	return append([]string(nil), n...), nil
}

func (rp *Replay) Readlink(path string) (string, error) {
	rec, ok := rp.b.getLink(path)
	if !ok {
		return "", rp.gap(fmt.Errorf("%w: Readlink %s", ErrNotRecorded, path))
	}
	if rec.notExist {
		return "", &fs.PathError{Op: "readlink", Path: path, Err: fs.ErrNotExist}
	}
	if rec.permission {
		return "", &fs.PathError{Op: "readlink", Path: path, Err: fs.ErrPermission}
	}
	if rec.errText != "" {
		return "", errors.New(rec.errText)
	}
	return rec.target, nil
}

func (rp *Replay) Stat(path string) (FileMeta, error) { return rp.stat(path, true) }

// stat is Stat; count says whether a miss is a recording gap. A size probe that
// tolerates the miss (StatProbe) is not one.
func (rp *Replay) stat(path string, count bool) (FileMeta, error) {
	rec, ok := rp.b.getStat(path)
	if !ok {
		err := fmt.Errorf("%w: Stat %s", ErrNotRecorded, path)
		if count {
			_ = rp.gap(err)
		}
		return FileMeta{}, err
	}
	if rec.notExist {
		return FileMeta{}, &fs.PathError{Op: "stat", Path: path, Err: fs.ErrNotExist}
	}
	if rec.permission {
		return FileMeta{}, &fs.PathError{Op: "stat", Path: path, Err: fs.ErrPermission}
	}
	if rec.errText != "" {
		return FileMeta{}, errors.New(rec.errText)
	}
	return rec.meta, nil
}

func (rp *Replay) Statfs(path string) (StatfsInfo, error) {
	rec, ok := rp.b.getStatfs(path)
	if !ok {
		return StatfsInfo{}, rp.gap(fmt.Errorf("%w: Statfs %s", ErrNotRecorded, path))
	}
	if rec.notExist {
		return StatfsInfo{}, &fs.PathError{Op: "statfs", Path: path, Err: fs.ErrNotExist}
	}
	if rec.permission {
		return StatfsInfo{}, &fs.PathError{Op: "statfs", Path: path, Err: fs.ErrPermission}
	}
	if rec.errText != "" {
		return StatfsInfo{}, errors.New(rec.errText)
	}
	return rec.info, nil
}

func (rp *Replay) Cached(key string, _ func() ([]byte, error)) ([]byte, error) {
	// Never invokes produce — the recorded bytes are the only source of truth, so
	// no live probe runs on replay.
	rec, ok := rp.b.getFile(cacheKey(key))
	if !ok {
		return nil, rp.gap(fmt.Errorf("%w: Cached %s", ErrNotRecorded, key))
	}
	if rec.errText != "" {
		return nil, errors.New(rec.errText)
	}
	return append([]byte(nil), rec.data...), nil
}

func (rp *Replay) Run(ctx context.Context, name string, args ...string) (Result, error) {
	rec, ok := rp.b.getCmd(name, args)
	if !ok {
		return Result{}, rp.gap(fmt.Errorf("%w: Run %s %v", ErrNotRecorded, name, args))
	}
	if rec.absent {
		// Reproduce a genuine spawn failure (e.g. tool not installed).
		return rec.res, &exec.Error{Name: name, Err: exec.ErrNotFound}
	}
	return rec.res, nil
}

// StatProbe is src.Stat for a best-effort probe whose caller tolerates a miss
// (collectors' size hint before a read, which older bundles never recorded): a
// Replay does not count that miss as a recording gap.
func StatProbe(src Source, path string) (FileMeta, error) {
	if rp, ok := src.(*Replay); ok {
		return rp.stat(path, false)
	}
	return src.Stat(path)
}
