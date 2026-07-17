//go:build linux

package collectors

import (
	"testing"

	"github.com/keyorixhq/dashdiag/internal/source"
)

// TestReadIntFile_ReadError_Source covers sysctl.go:29.16,31.3 — the readFile
// error branch when the fixture bundle has no entry for the path.
func TestReadIntFile_ReadError_Source(t *testing.T) {
	// no t.Parallel(): withFixtureSource mutates the package-level activeSource.
	withFixtureSource(t, func(b *source.Bundle) {})
	_, err := readIntFile("/proc/sys/vm/swappiness")
	if err == nil {
		t.Error("expected error when file is not in replay bundle")
	}
}

// TestReadIntFile_ParseError_Source covers sysctl.go:33.25,35.3 — the
// strconv.Atoi error branch when the file contains non-numeric content.
func TestReadIntFile_ParseError_Source(t *testing.T) {
	// no t.Parallel(): withFixtureSource mutates the package-level activeSource.
	withFixtureSource(t, func(b *source.Bundle) {
		b.PutFile("/proc/sys/vm/swappiness", []byte("not-a-number\n"))
	})
	_, err := readIntFile("/proc/sys/vm/swappiness")
	if err == nil {
		t.Error("expected error parsing non-numeric sysctl content")
	}
}
