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

// TestLargestDirs_EmptyMountDefaultsToRoot guards the mount=="" -> "/" default
// branch. runCmd is faked so no real `du` runs: a real `du -sh` on every child
// of "/" would walk the entire host filesystem and time out on a full CI runner
// (macOS /System, ubuntu /usr+/opt) — and the real scan isn't what this test is
// about. No t.Parallel(): swapRunCmd requires the test be serial.
func TestLargestDirs_EmptyMountDefaultsToRoot(t *testing.T) {
	swapRunCmd(t, func(_ context.Context, _ string, args ...string) (string, error) {
		return "1.0K\t" + args[len(args)-1] + "\n", nil
	})
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

// TestLargestDirs_UnreadableMountFallsBackAndFails guards the os.ReadDir(mount)
// error branch: when the mount itself can't be listed (permission denied),
// LargestDirs must fall through to largestDirsFallback, which hits the exact
// same permission error and must propagate it rather than panicking or
// returning a misleading empty table.
func TestLargestDirs_UnreadableMountFallsBackAndFails(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("permission-bit semantics differ on Windows")
	}
	if os.Getuid() == 0 {
		t.Skip("running as root — cannot test a permission-denied dir because root bypasses permission bits")
	}

	parent := t.TempDir()
	locked := filepath.Join(parent, "locked")
	if err := os.MkdirAll(locked, 0o000); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(locked, 0o755) })

	_, err := LargestDirs(context.Background(), locked)
	if err == nil {
		t.Error("expected an error when both the primary read and the fallback can't list the mount")
	}
}

// TestLargestDirs_DuEmptyOutputSkipsChild guards the len(fields) < 1 skip in
// the du-output parser: a child whose `du -sh` invocation succeeds but
// returns empty/whitespace-only output must be silently skipped rather than
// panicking on an out-of-range field access.
func TestLargestDirs_DuEmptyOutputSkipsChild(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "f"), []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}

	swapRunCmd(t, func(context.Context, string, ...string) (string, error) {
		return "   \n", nil
	})

	got, err := LargestDirs(context.Background(), dir)
	if err != nil {
		t.Fatalf("LargestDirs: %v", err)
	}
	if len(got.Rows) != 0 {
		t.Errorf("expected the empty-du-output child to be skipped, got %+v", got.Rows)
	}
}

func TestParseDuSize_EmptyString(t *testing.T) {
	t.Parallel()
	if got := parseDuSize(""); got != 0 {
		t.Errorf("parseDuSize(\"\") = %d, want 0", got)
	}
}

// TestParseDuSize_NoUnitSuffixDefaultsToRawBytes guards the default branch of
// the unit switch. parseDuSize always strips the LAST character as a
// presumed unit suffix; when that character is actually a digit (no T/G/M/K
// unit at all — `du -h` output below 1024 bytes has no suffix), it falls
// through to default and the value is parsed from the remaining digits, which
// documents a real quirk: the final digit is dropped from the numeric value
// in this no-suffix case (an inherent tradeoff of the fixed
// strip-last-char approach; only used for approximate sort ordering, so exact
// precision on sub-1024-byte doesn't affect real sorting behaviour above).
func TestParseDuSize_NoUnitSuffixDefaultsToRawBytes(t *testing.T) {
	t.Parallel()
	if got := parseDuSize("512"); got != 51 {
		t.Errorf("parseDuSize(\"512\") = %d, want 51 (last digit dropped as the presumed unit suffix)", got)
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
