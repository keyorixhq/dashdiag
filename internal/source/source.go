// Package source abstracts every raw system input a collector reads — file
// contents, glob expansions, directory listings, and external command output —
// behind one interface, so the exact bytes a collector saw on real hardware can
// be recorded into a portable Bundle and replayed later on a developer machine,
// re-running the real collector code against real inputs.
//
// Three implementations:
//
//   - Live:     reads the running system (production behaviour, the default).
//   - Recorder: wraps another Source, tees every read/exec into a Bundle.
//   - Replay:   serves reads/execs from a Bundle and FAILS LOUD on any access
//     that was never recorded, so a recording gap surfaces as an error instead
//     of a phantom-healthy result.
//
// See docs/adr/0003-raw-input-capture-replay.md for the design and invariants.
package source

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// FormatVersion is written into every bundle manifest. A newer bundle is refused
// by an older binary with a clear message rather than mis-read.
const FormatVersion = "raw-v1"

// Result is the outcome of an external command: stdout, stderr, and exit code.
// Stderr and exit code are kept (unlike collectors.runCmd) because a faithful
// replay must reproduce tools that signal findings through a non-zero exit.
type Result struct {
	Stdout   []byte
	Stderr   []byte
	ExitCode int
}

// FileMeta is the subset of os.FileInfo a collector actually consults when it
// stats a path: whether it exists (carried by a nil error), its size, mode bits,
// and whether it is a directory. That is everything the gate / size / mode / dir
// checks in the collectors need, and it serialises trivially into a bundle so a
// `os.Stat`-style existence gate replays from the capture instead of probing the
// developer's own machine.
type FileMeta struct {
	Size    int64       `json:"size"`
	Mode    os.FileMode `json:"mode"`
	IsDir   bool        `json:"is_dir"`
	ModTime time.Time   `json:"mod_time"`
}

// Source is the read-only system-input surface a collector depends on.
type Source interface {
	// ReadFile returns the contents of path. A non-existent path returns an
	// error satisfying errors.Is(err, os.ErrNotExist).
	ReadFile(path string) ([]byte, error)
	// Glob expands a shell pattern with filepath.Glob semantics.
	Glob(pattern string) ([]string, error)
	// ReadDir returns the sorted entry names of dir.
	ReadDir(dir string) ([]string, error)
	// Readlink returns the target of the symlink at path (os.Readlink semantics).
	// A non-existent path returns an error satisfying errors.Is(err, os.ErrNotExist).
	Readlink(path string) (string, error)
	// Stat returns metadata for path with os.Stat semantics (symlinks followed).
	// A non-existent path returns an error satisfying errors.Is(err, os.ErrNotExist);
	// a present-but-unreadable path returns one satisfying errors.Is(err, os.ErrPermission).
	Stat(path string) (FileMeta, error)
	// Run executes name with args and returns its captured Result. The error is
	// non-nil only for an execution failure (tool absent, context cancelled),
	// NOT for a non-zero exit — inspect Result.ExitCode for that.
	Run(ctx context.Context, name string, args ...string) (Result, error)
}

// ErrNotRecorded is returned by Replay when a collector touches an input that was
// never captured. It is deliberately distinct from os.ErrNotExist: a missing
// recording is a gap to fix, not a system fact to trust.
var ErrNotRecorded = errors.New("source: input not present in replay bundle (recording gap)")

// cleanPath canonicalises a file or dir key so record and replay agree.
func cleanPath(p string) string { return filepath.Clean(p) }

// cmdKey canonicalises an argv into a single map key.
func cmdKey(name string, args []string) string {
	return strings.Join(append([]string{name}, args...), "\x00")
}
