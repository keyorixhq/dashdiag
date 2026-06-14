package collectors

// fsaccess.go — file/sysfs read helpers routed through the active source.
//
// Collectors that read /sys, /proc, or other files must go through these (not
// os.ReadFile / filepath.Glob directly) so `dsd capture --raw` records exactly
// what they read and `dsd replay` can serve it back. A collector still calling
// os.ReadFile directly works live but is invisible to capture/replay — migrating
// the remaining ones is ADR-0003 Phase 3.

// readFile returns the contents of path via the active source.
func readFile(path string) ([]byte, error) { return activeSource.ReadFile(path) }

// glob expands a shell pattern (filepath.Glob semantics) via the active source.
func glob(pattern string) ([]string, error) { return activeSource.Glob(pattern) }

// readDirNames returns the sorted entry names of dir via the active source.
func readDirNames(dir string) ([]string, error) { return activeSource.ReadDir(dir) }
