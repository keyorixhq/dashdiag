package collectors

// fsaccess.go — file/sysfs read helpers routed through the active source.
//
// Collectors that read /sys, /proc, or other files go through these (not
// os.ReadFile / filepath.Glob directly) so `dsd capture --raw` records exactly
// what they read and `dsd replay` can serve it back. No build tag — helpers
// are used by both Linux and darwin collectors (ADR-0003).

import (
	"bytes"
	"io"
)

// readFile returns the contents of path via the active source.
func readFile(path string) ([]byte, error) { return activeSource.ReadFile(path) }

// glob expands a shell pattern (filepath.Glob semantics) via the active source.
func glob(pattern string) ([]string, error) { return activeSource.Glob(pattern) }

// openFile reads path via the active source and returns an io.ReadCloser.
// Use this as a drop-in for os.Open where the caller passes the result to a
// parser that expects an io.Reader / io.ReadCloser. The file is read fully
// up front so the source can record it; the returned ReadCloser is in-memory.
func openFile(path string) (io.ReadCloser, error) {
	data, err := activeSource.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return io.NopCloser(bytes.NewReader(data)), nil
}

// ReadFileViaSource and GlobViaSource are exported for use by cmd/ callers
// (e.g. capture_raw.go) that need to read through the active source without
// importing internal implementation details.
func ReadFileViaSource(path string) ([]byte, error)  { return activeSource.ReadFile(path) }
func GlobViaSource(pattern string) ([]string, error) { return activeSource.Glob(pattern) }
