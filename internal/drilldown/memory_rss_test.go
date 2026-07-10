package drilldown

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"testing"
)

func writeMemStatusFixture(t *testing.T, procRoot string, pid int, name string, rssKB int) {
	t.Helper()
	dir := filepath.Join(procRoot, strconv.Itoa(pid))
	if err := os.MkdirAll(dir, 0755); err != nil {
		t.Fatalf("MkdirAll: %v", err)
	}
	content := fmt.Sprintf("Name:\t%s\nVmRSS:\t   %d kB\n", name, rssKB)
	if err := os.WriteFile(filepath.Join(dir, "status"), []byte(content), 0644); err != nil {
		t.Fatalf("WriteFile status: %v", err)
	}
}

func writeMeminfoFixture(t *testing.T, procRoot string, totalKB int) {
	t.Helper()
	content := fmt.Sprintf("MemTotal:       %d kB\nMemFree:        1000 kB\n", totalKB)
	if err := os.WriteFile(filepath.Join(procRoot, "meminfo"), []byte(content), 0644); err != nil {
		t.Fatalf("WriteFile meminfo: %v", err)
	}
}

func TestTopProcessesByRSSLinux(t *testing.T) {
	t.Parallel()
	procRoot := t.TempDir()
	writeMeminfoFixture(t, procRoot, 1_000_000)
	writeMemStatusFixture(t, procRoot, 321, "hoggy", 100_000)

	got, err := topProcessesByRSSLinuxAt(context.Background(), 5, procRoot)
	if err != nil {
		t.Fatalf("topProcessesByRSSLinuxAt: %v", err)
	}
	if len(got.Rows) != 1 {
		t.Fatalf("expected 1 row, got %d: %+v", len(got.Rows), got.Rows)
	}
	want := []string{"321", "10.0%", "97.7MB", "hoggy"}
	for i, w := range want {
		if got.Rows[0][i] != w {
			t.Errorf("row[%d] = %q, want %q (full row: %+v)", i, got.Rows[0][i], w, got.Rows[0])
		}
	}
}

func TestTopProcessesByRSSLinux_ZeroRSSExcluded(t *testing.T) {
	t.Parallel()
	procRoot := t.TempDir()
	writeMeminfoFixture(t, procRoot, 1_000_000)
	writeMemStatusFixture(t, procRoot, 111, "idle", 0)

	got, err := topProcessesByRSSLinuxAt(context.Background(), 5, procRoot)
	if err != nil {
		t.Fatalf("topProcessesByRSSLinuxAt: %v", err)
	}
	if len(got.Rows) != 0 {
		t.Errorf("expected process with zero RSS to be excluded, got %+v", got.Rows)
	}
}

func TestTopProcessesByRSSLinux_SortedDescending(t *testing.T) {
	t.Parallel()
	procRoot := t.TempDir()
	writeMeminfoFixture(t, procRoot, 1_000_000)
	writeMemStatusFixture(t, procRoot, 1, "small", 100)
	writeMemStatusFixture(t, procRoot, 2, "big", 50000)

	got, err := topProcessesByRSSLinuxAt(context.Background(), 5, procRoot)
	if err != nil {
		t.Fatalf("topProcessesByRSSLinuxAt: %v", err)
	}
	if len(got.Rows) != 2 {
		t.Fatalf("expected 2 rows, got %d: %+v", len(got.Rows), got.Rows)
	}
	if got.Rows[0][3] != "big" || got.Rows[1][3] != "small" {
		t.Errorf("expected rows sorted by RSS descending (big, small), got %+v", got.Rows)
	}
}

func TestTopProcessesByRSSLinux_LimitN(t *testing.T) {
	t.Parallel()
	procRoot := t.TempDir()
	writeMeminfoFixture(t, procRoot, 1_000_000)
	writeMemStatusFixture(t, procRoot, 1, "a", 100)
	writeMemStatusFixture(t, procRoot, 2, "b", 200)
	writeMemStatusFixture(t, procRoot, 3, "c", 300)

	got, err := topProcessesByRSSLinuxAt(context.Background(), 2, procRoot)
	if err != nil {
		t.Fatalf("topProcessesByRSSLinuxAt: %v", err)
	}
	if len(got.Rows) != 2 {
		t.Errorf("expected n=2 to cap rows at 2, got %d: %+v", len(got.Rows), got.Rows)
	}
}

func TestSystemTotalMemKB(t *testing.T) {
	t.Parallel()
	procRoot := t.TempDir()
	writeMeminfoFixture(t, procRoot, 8_000_000)

	if got := systemTotalMemKB(procRoot); got != 8_000_000 {
		t.Errorf("systemTotalMemKB() = %d, want 8000000", got)
	}
}

func TestSystemTotalMemKB_MissingFile(t *testing.T) {
	t.Parallel()
	if got := systemTotalMemKB(t.TempDir()); got != 0 {
		t.Errorf("systemTotalMemKB() with no meminfo = %d, want 0", got)
	}
}

// TestTopProcessesByRSSLinux_TruncatesToN guards the len(procs) > n cap: more
// memory-heavy processes than requested must be truncated to the top n by
// RSS, not merely sorted.
func TestTopProcessesByRSSLinux_TruncatesToN(t *testing.T) {
	t.Parallel()
	procRoot := t.TempDir()
	writeMeminfoFixture(t, procRoot, 1_000_000)
	writeMemStatusFixture(t, procRoot, 1, "a", 100)
	writeMemStatusFixture(t, procRoot, 2, "b", 200)
	writeMemStatusFixture(t, procRoot, 3, "c", 300)

	got, err := topProcessesByRSSLinuxAt(context.Background(), 2, procRoot)
	if err != nil {
		t.Fatalf("topProcessesByRSSLinuxAt: %v", err)
	}
	if len(got.Rows) != 2 {
		t.Fatalf("expected n=2 to cap rows at 2, got %d: %+v", len(got.Rows), got.Rows)
	}
	if got.Rows[0][3] != "c" {
		t.Errorf("expected process c (highest RSS) first, got %+v", got.Rows)
	}
}

// topProcessesByRSSMac is only invoked at runtime on darwin, but it's a plain
// function, callable directly on any host — mocking runCmd lets it be
// exercised on Linux CI too. No t.Parallel(): see swapRunCmd's doc comment.
func TestTopProcessesByRSSMac(t *testing.T) {
	swapRunCmd(t, func(_ context.Context, name string, args ...string) (string, error) {
		if name != "ps" {
			t.Fatalf("unexpected command: %s %v", name, args)
		}
		return "  PID %MEM    RSS COMM\n  456  10.0  2048 /Applications/Foo.app/Contents/MacOS/Foo\n", nil
	})

	got, err := topProcessesByRSSMac(context.Background(), 5)
	if err != nil {
		t.Fatalf("topProcessesByRSSMac: %v", err)
	}
	if len(got.Rows) != 1 {
		t.Fatalf("expected 1 row, got %d: %+v", len(got.Rows), got.Rows)
	}
	want := []string{"456", "10.0%", "2.0MB", "Foo"}
	for i, w := range want {
		if got.Rows[0][i] != w {
			t.Errorf("row[%d] = %q, want %q (full row: %+v)", i, got.Rows[0][i], w, got.Rows[0])
		}
	}
}

// TestTopProcessesByRSSMac_RunCmdError guards the error-propagation branch: a
// failing `ps` invocation must surface the error rather than a partial or
// empty result.
func TestTopProcessesByRSSMac_RunCmdError(t *testing.T) {
	swapRunCmd(t, func(context.Context, string, ...string) (string, error) {
		return "", errNotFound
	})

	_, err := topProcessesByRSSMac(context.Background(), 5)
	if err == nil {
		t.Error("expected an error when ps fails")
	}
}

// TestTopProcessesByRSSMac_ShortLineSkippedAndCappedAtN guards both the
// len(fields) < 4 malformed-line skip and the len(rows) >= n break in the
// same pass: a truncated ps line must be ignored, and a third well-formed
// line must not appear once n=2 rows are already collected.
func TestTopProcessesByRSSMac_ShortLineSkippedAndCappedAtN(t *testing.T) {
	swapRunCmd(t, func(_ context.Context, name string, args ...string) (string, error) {
		if name != "ps" {
			t.Fatalf("unexpected command: %s %v", name, args)
		}
		return "  PID %MEM    RSS COMM\n" +
			"  111\n" + // malformed — too few fields
			"  222  10.0  1024 procA\n" +
			"  333  20.0  2048 procB\n" +
			"  444  30.0  4096 procC\n", nil
	})

	got, err := topProcessesByRSSMac(context.Background(), 2)
	if err != nil {
		t.Fatalf("topProcessesByRSSMac: %v", err)
	}
	if len(got.Rows) != 2 {
		t.Fatalf("expected n=2 to cap rows at 2 (after skipping the malformed line), got %d: %+v", len(got.Rows), got.Rows)
	}
	if got.Rows[0][0] != "222" || got.Rows[1][0] != "333" {
		t.Errorf("expected rows for pids 222 then 333, got %+v", got.Rows)
	}
}
