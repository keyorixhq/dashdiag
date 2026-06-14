//go:build linux

package collectors

// fsaccess.go — file/sysfs read helpers routed through the active source.
//
// Collectors that read /sys, /proc, or other files go through these (not
// os.ReadFile / filepath.Glob directly) so `dsd capture --raw` records exactly
// what they read and `dsd replay` can serve it back. Every current caller is a
// Linux collector, so this file is build-tagged linux; ADR-0003 Phase 3 widens
// the migration (and this tag comes off, or a darwin variant is added) as the
// non-Linux collectors move over.

// readFile returns the contents of path via the active source.
func readFile(path string) ([]byte, error) { return activeSource.ReadFile(path) }

// glob expands a shell pattern (filepath.Glob semantics) via the active source.
func glob(pattern string) ([]string, error) { return activeSource.Glob(pattern) }
