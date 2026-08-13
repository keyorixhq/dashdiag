package source

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
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
// name is resolved via ResolveTrustedTool (trusted system dirs, never the
// inherited $PATH) before exec — see trustedexec.go.
func defaultExec(ctx context.Context, name string, args ...string) (Result, error) {
	cmd := exec.CommandContext(ctx, ResolveTrustedTool(name), args...)
	so, se := NewCapWriter(MaxCapturedOutput), NewCapWriter(MaxCapturedOutput)
	cmd.Stdout, cmd.Stderr = so, se
	err := cmd.Run()
	res := Result{Stdout: so.Bytes(), Stderr: se.Bytes()}
	if err != nil {
		if ee, ok := errors.AsType[*exec.ExitError](err); ok {
			res.ExitCode = ee.ExitCode()
			return res, nil // non-zero exit is data, not an exec failure
		}
		return res, err // tool absent / ctx cancelled / spawn error
	}
	return res, nil
}
