package source

import (
	"bytes"
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"syscall"
)

// Live reads the running system. It is the default Source in production.
type Live struct {
	// Exec, if set, runs external commands. Collectors inject their locale-safe
	// runner here so record and replay share the exact production exec path. When
	// nil, defaultExec is used (sufficient for this package's own tests).
	Exec func(ctx context.Context, name string, args ...string) (Result, error)
}

func (l Live) ReadFile(path string) ([]byte, error) { return os.ReadFile(path) } // #nosec G304 -- caller-supplied system path is the whole point

func (l Live) Glob(pattern string) ([]string, error) { return filepath.Glob(pattern) }

func (l Live) ReadDir(dir string) ([]string, error) {
	ents, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}
	names := make([]string, len(ents))
	for i, e := range ents {
		names[i] = e.Name()
	}
	sort.Strings(names)
	return names, nil
}

func (l Live) Readlink(path string) (string, error) { return os.Readlink(path) }

func (l Live) Stat(path string) (FileMeta, error) {
	fi, err := os.Stat(path)
	if err != nil {
		return FileMeta{}, err
	}
	return FileMeta{Size: fi.Size(), Mode: fi.Mode(), IsDir: fi.IsDir(), ModTime: fi.ModTime()}, nil
}

func (l Live) Statfs(path string) (StatfsInfo, error) {
	var st syscall.Statfs_t
	if err := syscall.Statfs(path, &st); err != nil {
		return StatfsInfo{}, err
	}
	// uint64() casts normalise field types that differ across linux/darwin
	// (e.g. Bsize is int64 on linux, uint32 on darwin).
	return StatfsInfo{
		Bsize:  uint64(st.Bsize), //nolint:unconvert,gosec // cross-platform field-type normalisation
		Blocks: uint64(st.Blocks),
		Bfree:  uint64(st.Bfree),
		Bavail: uint64(st.Bavail),
		Files:  uint64(st.Files),
		Ffree:  uint64(st.Ffree),
	}, nil
}

func (l Live) Cached(_ string, produce func() ([]byte, error)) ([]byte, error) {
	return produce() // live reads always recompute; nothing is cached
}

func (l Live) Run(ctx context.Context, name string, args ...string) (Result, error) {
	if l.Exec != nil {
		return l.Exec(ctx, name, args...)
	}
	return defaultExec(ctx, name, args...)
}

// defaultExec runs a command capturing stdout, stderr, and exit code. A non-zero
// exit is reported via Result.ExitCode with a nil error; only a real execution
// failure (binary not found, context cancelled) returns a non-nil error.
func defaultExec(ctx context.Context, name string, args ...string) (Result, error) {
	cmd := exec.CommandContext(ctx, name, args...)
	var so, se bytes.Buffer
	cmd.Stdout, cmd.Stderr = &so, &se
	err := cmd.Run()
	res := Result{Stdout: so.Bytes(), Stderr: se.Bytes()}
	if err != nil {
		var ee *exec.ExitError
		if errors.As(err, &ee) {
			res.ExitCode = ee.ExitCode()
			return res, nil // non-zero exit is data, not an exec failure
		}
		return res, err // tool absent / ctx cancelled / spawn error
	}
	return res, nil
}
