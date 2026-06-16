package collectors

// fsaccess.go — file/sysfs read helpers routed through the active source.
//
// Collectors that read /sys, /proc, or other files go through these (not
// os.ReadFile / filepath.Glob / os.Open / os.ReadDir directly) so
// `dsd capture --raw` records exactly what they read and `dsd replay` can
// serve it back. No build tag — helpers are used by Linux and darwin collectors.

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"io/fs"
	"path/filepath"
	"time"

	"github.com/keyorixhq/dashdiag/internal/source"
)

// cachedJSON makes a computed value (e.g. a gopsutil call that reads /proc via its
// own API, bypassing the file wrappers) hermetic under capture/replay. compute is
// run on a live or capture pass and its result recorded as JSON; on `dsd replay`
// the recorded JSON is decoded into out and compute is NEVER called — so no live
// probe runs. key must be stable and unique. out must be a non-nil pointer.
func cachedJSON(key string, compute func() (any, error), out any) error {
	data, err := activeSource.Cached(key, func() ([]byte, error) {
		v, e := compute()
		if e != nil {
			return nil, e
		}
		return json.Marshal(v)
	})
	if err != nil {
		return err
	}
	return json.Unmarshal(data, out)
}

// readFile returns the contents of path via the active source.
func readFile(path string) ([]byte, error) { return activeSource.ReadFile(path) }

// glob expands a shell pattern (filepath.Glob semantics) via the active source.
func glob(pattern string) ([]string, error) { return activeSource.Glob(pattern) }

// openFile reads path via the active source and returns an io.ReadCloser.
// Use this as a drop-in for os.Open where the caller passes the result to a
// parser that expects an io.Reader / io.ReadCloser.
func openFile(path string) (io.ReadCloser, error) {
	data, err := activeSource.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return io.NopCloser(bytes.NewReader(data)), nil
}

// readDirNames returns the sorted entry names of dir via the active source.
// Use for callers that only need names (no IsDir / Info needed).
func readDirNames(dir string) ([]string, error) { return activeSource.ReadDir(dir) }

// readLink returns the target of the symlink at path via the active source, so
// capture/replay reproduces it instead of os.Readlink hitting the live machine.
func readLink(path string) (string, error) { return activeSource.Readlink(path) }

// statFile returns metadata for path via the active source (os.Stat semantics),
// so an existence / size / mode / is-dir gate replays from the capture instead of
// os.Stat hitting the replaying machine. Use this as a drop-in for os.Stat.
func statFile(path string) (source.FileMeta, error) { return activeSource.Stat(path) }

// statFs returns filesystem statistics for path via the active source
// (syscall.Statfs semantics), so a disk-usage / mount-liveness probe replays from
// the capture instead of stat-ing the replaying machine's filesystem. Use as a
// drop-in for `syscall.Statfs(path, &st)` — the returned struct's fields mirror
// the syscall.Statfs_t fields collectors read (Blocks, Bsize, Bfree, …).
func statFs(path string) (source.StatfsInfo, error) { return activeSource.Statfs(path) }

// fileExists reports whether path exists, routed through the active source. Use
// this as a drop-in for the common `if _, err := os.Stat(p); err == nil` gate so
// the existence check is recorded and replayed rather than probing the live
// machine. A permission error counts as "exists" (present but unreadable), which
// matches os.Stat returning a non-os.IsNotExist error for that case.
func fileExists(path string) bool {
	_, err := statFile(path)
	if err == nil {
		return true
	}
	return errors.Is(err, fs.ErrPermission)
}

// readDirEntries returns a synthetic []fs.DirEntry for dir via the active
// source. IsDir() is derived by probing whether dir/name has children in the
// source — sufficient for the filter patterns used in collectors (skip dirs,
// include only files, walk sub-dirs by name).
func readDirEntries(dir string) ([]fs.DirEntry, error) {
	names, err := activeSource.ReadDir(dir)
	if err != nil {
		return nil, err
	}
	entries := make([]fs.DirEntry, len(names))
	for i, name := range names {
		entries[i] = fakeDirEntry{
			name:  name,
			isDir: probeIsDir(filepath.Join(dir, name)),
		}
	}
	return entries, nil
}

// probeIsDir returns true if path appears to be a directory in the active
// source: ReadDir succeeds (even if empty — an empty dir is still a dir).
func probeIsDir(path string) bool {
	_, err := activeSource.ReadDir(path)
	return err == nil
}

// fakeDirEntry satisfies fs.DirEntry with name and isDir only.
type fakeDirEntry struct {
	name  string
	isDir bool
}

func (f fakeDirEntry) Name() string               { return f.name }
func (f fakeDirEntry) IsDir() bool                { return f.isDir }
func (f fakeDirEntry) Type() fs.FileMode          { return 0 }
func (f fakeDirEntry) Info() (fs.FileInfo, error) { return fakeFileInfo(f), nil }

type fakeFileInfo struct {
	name  string
	isDir bool
}

func (f fakeFileInfo) Name() string       { return f.name }
func (f fakeFileInfo) Size() int64        { return 0 }
func (f fakeFileInfo) Mode() fs.FileMode  { return 0o644 }
func (f fakeFileInfo) ModTime() time.Time { return time.Time{} }
func (f fakeFileInfo) IsDir() bool        { return f.isDir }
func (f fakeFileInfo) Sys() any           { return nil }

// ReadFileViaSource, GlobViaSource, and ReadlinkViaSource are exported for
// callers outside the collectors package (cmd/, internal/analysis) that need
// source-routed reads without a collector context — so their sysfs reads are
// captured by `dsd capture --raw` and served by `dsd replay` instead of hitting
// the live machine.
func ReadFileViaSource(path string) ([]byte, error)  { return activeSource.ReadFile(path) }
func GlobViaSource(pattern string) ([]string, error) { return activeSource.Glob(pattern) }
func ReadlinkViaSource(path string) (string, error)  { return activeSource.Readlink(path) }
