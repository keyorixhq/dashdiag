package collectors

// fsaccess.go — file/sysfs read helpers routed through the active source.
//
// Collectors that read /sys, /proc, or other files go through these (not
// os.ReadFile / filepath.Glob / os.Open / os.ReadDir directly) so
// `dsd capture --raw` records exactly what they read and `dsd replay` can
// serve it back. No build tag — helpers are used by Linux and darwin collectors.

import (
	"bytes"
	"io"
	"io/fs"
	"path/filepath"
	"time"
)

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

// ReadFileViaSource and GlobViaSource are exported for cmd/ callers (e.g.
// capture_raw.go) that need source-routed reads without a collector context.
func ReadFileViaSource(path string) ([]byte, error)  { return activeSource.ReadFile(path) }
func GlobViaSource(pattern string) ([]string, error) { return activeSource.Glob(pattern) }
