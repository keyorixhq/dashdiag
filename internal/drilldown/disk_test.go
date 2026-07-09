package drilldown

import (
	"context"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// TestLargestDirsHonestAboutUnreadableChild guards a false-OK-by-omission bug:
// a child directory `du -sh` cannot read (permission denied) was previously
// dropped with zero trace, so the table could show smaller readable dirs as
// the top disk consumers while the real hog — an unreadable dir — silently
// vanished. LargestDirs must now surface a Note counting what it couldn't
// measure instead of pretending nothing was skipped.
func TestLargestDirsHonestAboutUnreadableChild(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("permission-bit semantics differ on Windows")
	}
	if os.Getuid() == 0 {
		t.Skip("running as root — cannot test a permission-denied child because root bypasses permission bits")
	}

	dir := t.TempDir()
	readable := filepath.Join(dir, "readable")
	if err := os.MkdirAll(readable, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(readable, "f"), []byte("hello"), 0o644); err != nil {
		t.Fatal(err)
	}
	locked := filepath.Join(dir, "locked")
	if err := os.MkdirAll(locked, 0o000); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(locked, 0o755) }) // let TempDir cleanup remove it

	d, err := LargestDirs(context.Background(), dir)
	if err != nil {
		t.Fatalf("LargestDirs returned an error: %v", err)
	}
	if d == nil {
		t.Fatal("expected a details table, got nil")
	}
	if d.Note == "" || !strings.Contains(d.Note, "could not be measured") {
		t.Errorf("expected an honest skipped-entry note, got %q", d.Note)
	}
	found := false
	for _, row := range d.Rows {
		if strings.Contains(row[1], "readable") {
			found = true
		}
	}
	if !found {
		t.Errorf("the readable directory should still appear in rows: %+v", d.Rows)
	}
}

// TestLargestDirs_HappyPath exercises LargestDirs directly against a plain
// t.TempDir() fixture with real subdirectories (no permission-denied child),
// via the real `du` binary — LargestDirs has no injectable-root variant
// (unlike the topProcessesBy*LinuxAt functions), so the fixture dir is passed
// straight as the mount argument.
func TestLargestDirs_HappyPath(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	sub := filepath.Join(dir, "data")
	if err := os.MkdirAll(sub, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(sub, "f"), []byte("hello world"), 0o644); err != nil {
		t.Fatal(err)
	}

	got, err := LargestDirs(context.Background(), dir)
	if err != nil {
		t.Fatalf("LargestDirs: %v", err)
	}
	if got == nil {
		t.Fatal("expected non-nil Details")
	}
	if got.Type != "directory_sizes" {
		t.Errorf("unexpected Type: %q", got.Type)
	}
	found := false
	for _, row := range got.Rows {
		if strings.Contains(row[1], "data") {
			found = true
		}
	}
	if !found {
		t.Errorf("expected the data subdirectory in rows: %+v", got.Rows)
	}
	if got.Note != "" {
		t.Errorf("expected no skipped-entry note when nothing was unreadable, got %q", got.Note)
	}
}

// TestLargestDirs_EmptyMountDefaultsToRoot guards the mount=="" -> "/"
// default branch.
func TestLargestDirs_EmptyMountDefaultsToRoot(t *testing.T) {
	t.Parallel()
	got, err := LargestDirs(context.Background(), "")
	if err != nil {
		t.Fatalf("LargestDirs: %v", err)
	}
	if got == nil {
		t.Fatal("expected non-nil Details")
	}
	if !strings.Contains(got.Title, "/") {
		t.Errorf("expected title to reference the default mount, got %q", got.Title)
	}
}

func TestPluralIes(t *testing.T) {
	t.Parallel()
	cases := []struct {
		n    int
		want string
	}{
		{0, "ies"},
		{1, "y"},
		{2, "ies"},
		{5, "ies"},
	}
	for _, c := range cases {
		if got := pluralIes(c.n); got != c.want {
			t.Errorf("pluralIes(%d) = %q, want %q", c.n, got, c.want)
		}
	}
}

func TestParseDuSize_Ordering(t *testing.T) {
	// du -h units are 1024-based; cross-unit comparisons must order correctly.
	// 1023M < 1G < 2G < 1T, and 900K < 1M.
	ordered := []string{"512K", "900K", "1M", "1023M", "1G", "2G", "1T"}
	for i := 1; i < len(ordered); i++ {
		lo, hi := parseDuSize(ordered[i-1]), parseDuSize(ordered[i])
		if lo >= hi {
			t.Errorf("parseDuSize(%q)=%d should be < parseDuSize(%q)=%d", ordered[i-1], lo, ordered[i], hi)
		}
	}
	// 1G must be 1024^3 bytes.
	if got := parseDuSize("1G"); got != 1024*1024*1024 {
		t.Errorf("parseDuSize(1G) = %d, want %d", got, 1024*1024*1024)
	}
}
