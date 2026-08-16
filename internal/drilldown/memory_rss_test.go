package drilldown

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"testing"

	"github.com/keyorixhq/dashdiag/internal/platform"
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
	// No t.Parallel(): swapDetectContainerContext mutates package state.
	swapDetectContainerContext(t, func() platform.ContainerContext { return platform.ContainerContext{} })
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

// TestTopProcessesByRSSLinux_MissingStatusFileSkipped guards the os.Open
// error branch: a PID directory whose "status" file vanished between the
// /proc listing and the read (the process exited mid-scan) must be silently
// skipped rather than erroring the whole scan.
func TestTopProcessesByRSSLinux_MissingStatusFileSkipped(t *testing.T) {
	t.Parallel()
	procRoot := t.TempDir()
	writeMeminfoFixture(t, procRoot, 1_000_000)
	const pid = 654
	dir := filepath.Join(procRoot, strconv.Itoa(pid))
	// Create the PID directory (so walkProcs treats it as a valid PID) but
	// deliberately omit the "status" file entirely.
	if err := os.MkdirAll(dir, 0755); err != nil {
		t.Fatalf("MkdirAll: %v", err)
	}

	got, err := topProcessesByRSSLinuxAt(context.Background(), 5, procRoot)
	if err != nil {
		t.Fatalf("topProcessesByRSSLinuxAt: %v", err)
	}
	if len(got.Rows) != 0 {
		t.Errorf("expected the process with a missing status file to be skipped, got %+v", got.Rows)
	}
}

// TestTopProcessesByRSSLinux_PermissionDeniedSetsPartial is the regression
// test for the false-OK fix (internal-drilldown-02-03): a permission-denied
// /proc/<pid>/status read (owned by another user) must flip the partial flag
// and surface an honest Note rather than silently vanishing from the ranking
// the same way a genuinely-exited process does — mirrors
// TestTopProcessesBySwapLinux_PermissionDeniedSetsPartial (swap_test.go),
// whose partial+Note pattern this replicates for RSS. A directory with mode
// 0000 triggers EACCES for a non-root reader.
func TestTopProcessesByRSSLinux_PermissionDeniedSetsPartial(t *testing.T) {
	t.Parallel()
	if os.Geteuid() == 0 {
		t.Skip("running as root — permission bits don't block the read")
	}
	procRoot := t.TempDir()
	writeMeminfoFixture(t, procRoot, 1_000_000)
	const pid = 654
	dir := filepath.Join(procRoot, strconv.Itoa(pid))
	if err := os.MkdirAll(dir, 0000); err != nil {
		t.Fatalf("MkdirAll: %v", err)
	}
	t.Cleanup(func() { _ = os.Chmod(dir, 0755) }) // TempDir cleanup needs read perms restored

	got, err := topProcessesByRSSLinuxAt(context.Background(), 5, procRoot)
	if err != nil {
		t.Fatalf("topProcessesByRSSLinuxAt: %v", err)
	}
	if len(got.Rows) != 0 {
		t.Errorf("expected the permission-denied process to be excluded from rows, got %+v", got.Rows)
	}
	if got.Note == "" {
		t.Error("expected a partial-visibility note when /proc/<pid>/status is permission-denied")
	}
}

// TestTopProcessesByRSSLinux_MissingStatusFileNotPartial is the companion
// boundary guard: a genuinely-vanished status file (ENOENT, not EACCES —
// TestTopProcessesByRSSLinux_MissingStatusFileSkipped's scenario) must NOT
// set the partial flag or Note, since nothing was actually hidden by
// insufficient privilege.
func TestTopProcessesByRSSLinux_MissingStatusFileNotPartial(t *testing.T) {
	t.Parallel()
	procRoot := t.TempDir()
	writeMeminfoFixture(t, procRoot, 1_000_000)
	const pid = 655
	dir := filepath.Join(procRoot, strconv.Itoa(pid))
	if err := os.MkdirAll(dir, 0755); err != nil {
		t.Fatalf("MkdirAll: %v", err)
	}

	got, err := topProcessesByRSSLinuxAt(context.Background(), 5, procRoot)
	if err != nil {
		t.Fatalf("topProcessesByRSSLinuxAt: %v", err)
	}
	if got.Note != "" {
		t.Errorf("expected no partial-visibility note for a genuinely-vanished status file, got %q", got.Note)
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

// TestSystemTotalMemKB_NoMemTotalLine guards the fall-through-to-0 return: a
// meminfo file that exists and parses but never contains a "MemTotal:" line
// (a stripped-down or corrupted fixture) must yield 0, not panic on an empty
// scan.
func TestSystemTotalMemKB_NoMemTotalLine(t *testing.T) {
	t.Parallel()
	procRoot := t.TempDir()
	if err := os.WriteFile(filepath.Join(procRoot, "meminfo"), []byte("MemFree:    1000 kB\n"), 0644); err != nil {
		t.Fatalf("WriteFile meminfo: %v", err)
	}

	if got := systemTotalMemKB(procRoot); got != 0 {
		t.Errorf("systemTotalMemKB() with no MemTotal line = %d, want 0", got)
	}
}

// TestEffectiveTotalMemKB_NotInContainerFallsBackToSystemTotal is the
// baseline case: outside a container, effectiveTotalMemKB must return the
// same value systemTotalMemKB does.
func TestEffectiveTotalMemKB_NotInContainerFallsBackToSystemTotal(t *testing.T) {
	swapDetectContainerContext(t, func() platform.ContainerContext { return platform.ContainerContext{} })
	procRoot := t.TempDir()
	writeMeminfoFixture(t, procRoot, 8_000_000)

	if got := effectiveTotalMemKB(procRoot); got != 8_000_000 {
		t.Errorf("effectiveTotalMemKB() = %d, want 8000000 (host meminfo total)", got)
	}
}

// TestEffectiveTotalMemKB_InContainerUsesMemLimit is the regression test for
// internal-drilldown-02-02: inside a container with a cgroup memory limit,
// effectiveTotalMemKB must use the container's ceiling, not the host's
// /proc/meminfo MemTotal (which reflects the HOST's total RAM and would
// wildly understate MEM% for every process).
func TestEffectiveTotalMemKB_InContainerUsesMemLimit(t *testing.T) {
	swapDetectContainerContext(t, func() platform.ContainerContext {
		return platform.ContainerContext{InContainer: true, MemLimitMB: 512}
	})
	procRoot := t.TempDir()
	// Host meminfo reports a much larger total — must be ignored in favour of
	// the container's 512MB limit.
	writeMeminfoFixture(t, procRoot, 64_000_000)

	want := int64(512 * 1024)
	if got := effectiveTotalMemKB(procRoot); got != want {
		t.Errorf("effectiveTotalMemKB() = %d, want %d (container mem limit, not host meminfo total)", got, want)
	}
}

// TestEffectiveTotalMemKB_InContainerNoLimitFallsBackToSystemTotal covers an
// unlimited container (cgroup memory.max == "max", so MemLimitMB parses to
// 0) — there's no real ceiling to use, so this must fall back to the host
// total rather than reporting a bogus zero (which would blank out every
// MEM% column via the totalKB > 0 guard).
func TestEffectiveTotalMemKB_InContainerNoLimitFallsBackToSystemTotal(t *testing.T) {
	swapDetectContainerContext(t, func() platform.ContainerContext {
		return platform.ContainerContext{InContainer: true, MemLimitMB: 0}
	})
	procRoot := t.TempDir()
	writeMeminfoFixture(t, procRoot, 8_000_000)

	if got := effectiveTotalMemKB(procRoot); got != 8_000_000 {
		t.Errorf("effectiveTotalMemKB() = %d, want 8000000 (fallback to host meminfo total)", got)
	}
}

// TestTopProcessesByRSSLinux_ContainerMemLimitOverridesTotal is the
// end-to-end regression test for internal-drilldown-02-02: MEM% for the top
// processes must be computed against the container's effective memory limit,
// not the host-wide /proc/meminfo total that systemTotalMemKB alone would
// have used.
func TestTopProcessesByRSSLinux_ContainerMemLimitOverridesTotal(t *testing.T) {
	// No t.Parallel(): swapDetectContainerContext mutates package state.
	swapDetectContainerContext(t, func() platform.ContainerContext {
		return platform.ContainerContext{InContainer: true, MemLimitMB: 1000} // 1,024,000 KB
	})
	procRoot := t.TempDir()
	// Host total is 64x the container limit — if this leaked through, MEM%
	// would be computed as ~0.15% instead of the correct ~10%.
	writeMeminfoFixture(t, procRoot, 64_000_000)
	writeMemStatusFixture(t, procRoot, 321, "hoggy", 100_000)

	got, err := topProcessesByRSSLinuxAt(context.Background(), 5, procRoot)
	if err != nil {
		t.Fatalf("topProcessesByRSSLinuxAt: %v", err)
	}
	if len(got.Rows) != 1 {
		t.Fatalf("expected 1 row, got %d: %+v", len(got.Rows), got.Rows)
	}
	// 100,000 / 1,024,000 * 100 = 9.765625% -> "9.8%"
	want := "9.8%"
	if got.Rows[0][1] != want {
		t.Errorf("MEM%% = %q, want %q (must use container limit, not host meminfo total)", got.Rows[0][1], want)
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
