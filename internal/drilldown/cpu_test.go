package drilldown

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"testing"
	"time"
)

func writeProcStatFixture(t *testing.T, procRoot string, pid int, state string, ppid, utime, stime int) {
	t.Helper()
	dir := filepath.Join(procRoot, strconv.Itoa(pid))
	if err := os.MkdirAll(dir, 0755); err != nil {
		t.Fatalf("MkdirAll: %v", err)
	}
	// pid (comm) state ppid pgrp session tty_nr tpgid flags minflt cminflt majflt cmajflt utime stime ...
	line := fmt.Sprintf("%d (fixtureproc) %s %d 0 0 0 0 0 0 0 0 0 %d %d 0 0 20 0 1 0\n",
		pid, state, ppid, utime, stime)
	if err := os.WriteFile(filepath.Join(dir, "stat"), []byte(line), 0644); err != nil {
		t.Fatalf("WriteFile stat: %v", err)
	}
}

func writeSystemStatFixture(t *testing.T, procRoot string, totalJiffies int) {
	t.Helper()
	content := fmt.Sprintf("cpu  %d 0 0 0 0 0 0 0\n", totalJiffies)
	if err := os.WriteFile(filepath.Join(procRoot, "stat"), []byte(content), 0644); err != nil {
		t.Fatalf("WriteFile /stat: %v", err)
	}
}

// TestTopProcessesByCPULinux_Sorting exercises the real two-sample delta path
// against a fixture /proc tree instead of the live filesystem (per the
// project's own testdata/fixtures rule). It mutates the fixture mid-flight to
// simulate CPU ticks accruing between topProcessesByCPULinuxAt's two internal
// samples (200ms apart).
func TestTopProcessesByCPULinux_Sorting(t *testing.T) {
	procRoot := t.TempDir()
	const pid = 123

	writeSystemStatFixture(t, procRoot, 1000)
	writeProcStatFixture(t, procRoot, pid, "R", 1, 500, 200) // ticks0 = 700

	go func() {
		time.Sleep(30 * time.Millisecond)
		writeSystemStatFixture(t, procRoot, 1300)                // delta total = 300
		writeProcStatFixture(t, procRoot, pid, "R", 1, 600, 300) // ticks1 = 900, delta = 200
	}()

	got, err := topProcessesByCPULinuxAt(context.Background(), 5, procRoot)
	if err != nil {
		t.Fatalf("topProcessesByCPULinuxAt: %v", err)
	}
	if len(got.Rows) != 1 {
		t.Fatalf("expected 1 row, got %d: %+v", len(got.Rows), got.Rows)
	}
	row := got.Rows[0]
	if row[0] != strconv.Itoa(pid) {
		t.Errorf("row PID = %q, want %q", row[0], strconv.Itoa(pid))
	}
	if row[2] != "fixtureproc" {
		t.Errorf("row COMMAND = %q, want %q", row[2], "fixtureproc")
	}
	wantPct := 200.0 / 300.0 * float64(runtime.NumCPU()) * 100
	wantStr := fmt.Sprintf("%.1f%%", wantPct)
	if row[1] != wantStr {
		t.Errorf("row CPU%% = %q, want %q", row[1], wantStr)
	}
}

// TestTopProcessesByCPULinuxAt_ContextCancelled guards the ctx.Done() branch
// hit between the two sampling passes: a context cancelled before the 200ms
// gap elapses must return ctx.Err(), not silently proceed to a second
// sample.
func TestTopProcessesByCPULinuxAt_ContextCancelled(t *testing.T) {
	t.Parallel()
	procRoot := t.TempDir()
	writeSystemStatFixture(t, procRoot, 1000)
	writeProcStatFixture(t, procRoot, 1, "R", 1, 100, 0)

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	_, err := topProcessesByCPULinuxAt(ctx, 5, procRoot)
	if err == nil {
		t.Error("expected an error from a pre-cancelled context")
	}
}

// TestTopProcessesByCPULinux_MalformedStatLineSkipped guards the "!ok ||
// len(rest) < 13" defensive skip: an unreadable-shape /proc/<pid>/stat entry
// must be ignored rather than panicking on a short field slice.
func TestTopProcessesByCPULinux_MalformedStatLineSkipped(t *testing.T) {
	t.Parallel()
	procRoot := t.TempDir()
	writeSystemStatFixture(t, procRoot, 1000)
	if err := os.MkdirAll(filepath.Join(procRoot, "1"), 0755); err != nil {
		t.Fatalf("MkdirAll: %v", err)
	}
	// Too few fields after "comm)" to reach the utime/stime indices.
	if err := os.WriteFile(filepath.Join(procRoot, "1", "stat"), []byte("1 (short) R 1 0 0\n"), 0644); err != nil {
		t.Fatalf("WriteFile stat: %v", err)
	}

	got, err := topProcessesByCPULinuxAt(context.Background(), 5, procRoot)
	if err != nil {
		t.Fatalf("topProcessesByCPULinuxAt: %v", err)
	}
	if len(got.Rows) != 0 {
		t.Errorf("expected the malformed stat entry to be skipped, got %+v", got.Rows)
	}
}

// TestTopProcessesByCPULinux_RecycledPIDSkipped guards the "cpuTicks went
// backwards" skip: if a PID's ticks in the second sample are lower than in
// the first, the PID must have been recycled by a new process between
// samples and must be excluded rather than wrapping to a huge bogus rate.
func TestTopProcessesByCPULinux_RecycledPIDSkipped(t *testing.T) {
	procRoot := t.TempDir()
	const pid = 5
	writeSystemStatFixture(t, procRoot, 1000)
	writeProcStatFixture(t, procRoot, pid, "R", 1, 5000, 5000) // ticks0 = 10000 (high)

	go func() {
		time.Sleep(30 * time.Millisecond)
		writeSystemStatFixture(t, procRoot, 1300)
		writeProcStatFixture(t, procRoot, pid, "R", 1, 10, 10) // ticks1 = 20 (recycled, lower)
	}()

	got, err := topProcessesByCPULinuxAt(context.Background(), 5, procRoot)
	if err != nil {
		t.Fatalf("topProcessesByCPULinuxAt: %v", err)
	}
	if len(got.Rows) != 0 {
		t.Errorf("expected the recycled pid to be skipped, got %+v", got.Rows)
	}
}

// TestTopProcessesByCPULinux_NewPidMidWindowSkipped guards the "PID appeared
// mid-window" branch: a process present only in the second sample (no
// baseline in s0) must be skipped rather than treated as a huge delta.
func TestTopProcessesByCPULinux_NewPidMidWindowSkipped(t *testing.T) {
	procRoot := t.TempDir()
	writeSystemStatFixture(t, procRoot, 1000)
	writeProcStatFixture(t, procRoot, 1, "R", 1, 100, 0) // present in both, no activity

	go func() {
		time.Sleep(30 * time.Millisecond)
		writeSystemStatFixture(t, procRoot, 1300)
		writeProcStatFixture(t, procRoot, 2, "R", 1, 50, 0) // new pid, only in s1
	}()

	got, err := topProcessesByCPULinuxAt(context.Background(), 5, procRoot)
	if err != nil {
		t.Fatalf("topProcessesByCPULinuxAt: %v", err)
	}
	for _, row := range got.Rows {
		if row[0] == "2" {
			t.Errorf("pid 2 appeared only in the second sample and should be skipped, got row %+v", row)
		}
	}
}

// TestTopProcessesByCPULinux_UnreadableStatEntrySkipped guards the
// os.ReadFile error branch inside sample(): a /proc/<pid> directory whose
// stat file can't be opened (removed mid-scan, permission gap, etc.) must be
// silently skipped rather than propagating an error.
func TestTopProcessesByCPULinux_UnreadableStatEntrySkipped(t *testing.T) {
	t.Parallel()
	procRoot := t.TempDir()
	writeSystemStatFixture(t, procRoot, 1000)
	// PID directory exists (so walkProcs enumerates it) but has no stat file.
	if err := os.MkdirAll(filepath.Join(procRoot, "9"), 0755); err != nil {
		t.Fatalf("MkdirAll: %v", err)
	}

	got, err := topProcessesByCPULinuxAt(context.Background(), 5, procRoot)
	if err != nil {
		t.Fatalf("topProcessesByCPULinuxAt: %v", err)
	}
	if len(got.Rows) != 0 {
		t.Errorf("expected the unreadable stat entry to be skipped, got %+v", got.Rows)
	}
}

func TestTopProcessesByCPULinux_NoProcesses(t *testing.T) {
	procRoot := t.TempDir()
	writeSystemStatFixture(t, procRoot, 1000)

	got, err := topProcessesByCPULinuxAt(context.Background(), 5, procRoot)
	if err != nil {
		t.Fatalf("topProcessesByCPULinuxAt: %v", err)
	}
	if len(got.Rows) != 0 {
		t.Errorf("expected no rows with no /proc/<pid> entries, got %+v", got.Rows)
	}
}

func TestSystemTotalJiffies(t *testing.T) {
	t.Parallel()
	procRoot := t.TempDir()
	writeSystemStatFixture(t, procRoot, 4242)

	if got := systemTotalJiffies(procRoot); got != 4242 {
		t.Errorf("systemTotalJiffies() = %d, want 4242", got)
	}
}

func TestSystemTotalJiffies_MissingFile(t *testing.T) {
	t.Parallel()
	if got := systemTotalJiffies(t.TempDir()); got != 0 {
		t.Errorf("systemTotalJiffies() with no /stat file = %d, want 0", got)
	}
}

// TestSystemTotalJiffies_NoCPULine guards the fall-through-the-scanner path:
// the /stat file exists and is readable but contains no "cpu " line at all
// (distinct from the missing-file case above, which returns via os.Open
// erroring). Both must yield 0, but they exercise different statements.
func TestSystemTotalJiffies_NoCPULine(t *testing.T) {
	t.Parallel()
	procRoot := t.TempDir()
	if err := os.WriteFile(filepath.Join(procRoot, "stat"), []byte("intr 12345\nctxt 6789\n"), 0644); err != nil {
		t.Fatalf("WriteFile stat: %v", err)
	}
	if got := systemTotalJiffies(procRoot); got != 0 {
		t.Errorf("systemTotalJiffies() with no cpu line = %d, want 0", got)
	}
}

// TestTopProcessesByCPULinux_TruncatesToN guards the len(entries) > n cap:
// more busy processes than requested must be truncated to the top n by
// CPU%, not merely sorted.
func TestTopProcessesByCPULinux_TruncatesToN(t *testing.T) {
	procRoot := t.TempDir()
	writeSystemStatFixture(t, procRoot, 1000)
	writeProcStatFixture(t, procRoot, 1, "R", 1, 100, 0)
	writeProcStatFixture(t, procRoot, 2, "R", 1, 200, 0)
	writeProcStatFixture(t, procRoot, 3, "R", 1, 300, 0)

	go func() {
		time.Sleep(30 * time.Millisecond)
		writeSystemStatFixture(t, procRoot, 1300)
		writeProcStatFixture(t, procRoot, 1, "R", 1, 150, 0) // +50
		writeProcStatFixture(t, procRoot, 2, "R", 1, 260, 0) // +60
		writeProcStatFixture(t, procRoot, 3, "R", 1, 400, 0) // +100 (busiest)
	}()

	got, err := topProcessesByCPULinuxAt(context.Background(), 2, procRoot)
	if err != nil {
		t.Fatalf("topProcessesByCPULinuxAt: %v", err)
	}
	if len(got.Rows) != 2 {
		t.Fatalf("expected n=2 to cap rows at 2, got %d: %+v", len(got.Rows), got.Rows)
	}
	if got.Rows[0][0] != "3" {
		t.Errorf("expected pid 3 (busiest) first, got %+v", got.Rows)
	}
}

// TestTopProcessesByCPUMac_RunCmdError guards the error-propagation branch:
// a failing `ps` invocation must surface the error rather than a partial
// or empty result.
func TestTopProcessesByCPUMac_RunCmdError(t *testing.T) {
	swapRunCmd(t, func(context.Context, string, ...string) (string, error) {
		return "", errNotFound
	})

	_, err := topProcessesByCPUMac(context.Background(), 5)
	if err == nil {
		t.Error("expected an error when ps fails")
	}
}

// TestTopProcessesByCPUMac_ShortLineSkipped guards the len(fields) < 3
// malformed-line skip: a truncated ps line must be ignored, not panic or
// produce a bogus row.
func TestTopProcessesByCPUMac_ShortLineSkipped(t *testing.T) {
	swapRunCmd(t, func(_ context.Context, name string, args ...string) (string, error) {
		if name != "ps" {
			t.Fatalf("unexpected command: %s %v", name, args)
		}
		return "  PID  %CPU COMMAND\n  123\n  456   2.0 good\n", nil
	})

	got, err := topProcessesByCPUMac(context.Background(), 5)
	if err != nil {
		t.Fatalf("topProcessesByCPUMac: %v", err)
	}
	if len(got.Rows) != 1 || got.Rows[0][0] != "456" {
		t.Errorf("expected only the well-formed row to survive, got %+v", got.Rows)
	}
}

// TestTopProcessesByCPU_RealProc exercises the exported dispatcher and its
// Linux hardcoded-"/proc" wrapper against the ACTUAL /proc of the test
// container (real, uncancelled context) — the established pattern for these
// thin GOOS-switch wrappers in this package (they're already covered
// indirectly via PopulateAll's cancelled-context test for other checks; this
// is the direct-call variant used to actually let them complete and be
// measured). The container always has a live process table (PID 1, this test
// process, etc.), so this only asserts "no panic, no error, plausible
// result" — exact values are already covered by *LinuxAt above.
func TestTopProcessesByCPU_RealProc(t *testing.T) {
	got, err := TopProcessesByCPU(context.Background(), 5)
	if err != nil {
		t.Fatalf("TopProcessesByCPU: %v", err)
	}
	if got == nil {
		t.Fatal("expected non-nil Details from a real /proc read")
	}
	if got.Type != "process_table" || got.Title != "Top processes by CPU%" {
		t.Errorf("unexpected shape: %+v", got)
	}
	if len(got.Rows) > 5 {
		t.Errorf("expected at most 5 rows, got %d", len(got.Rows))
	}
}

// topProcessesByCPUMac is only invoked at runtime on darwin, but it's a plain
// function, callable directly on any host — mocking runCmd lets it be
// exercised on Linux CI too. No t.Parallel(): see swapRunCmd's doc comment.
func TestTopProcessesByCPUMac(t *testing.T) {
	swapRunCmd(t, func(_ context.Context, name string, args ...string) (string, error) {
		if name != "ps" {
			t.Fatalf("unexpected command: %s %v", name, args)
		}
		return "  PID  %CPU COMMAND\n  123   5.0 myproc\n", nil
	})

	got, err := topProcessesByCPUMac(context.Background(), 5)
	if err != nil {
		t.Fatalf("topProcessesByCPUMac: %v", err)
	}
	if len(got.Rows) != 1 {
		t.Fatalf("expected 1 row, got %d: %+v", len(got.Rows), got.Rows)
	}
	want := []string{"123", "5.0%", "myproc"}
	for i, w := range want {
		if got.Rows[0][i] != w {
			t.Errorf("row[%d] = %q, want %q (full row: %+v)", i, got.Rows[0][i], w, got.Rows[0])
		}
	}
}

// TestTopProcessesByCPUMac_CapsAtN guards the len(rows) >= n break: with more
// well-formed ps lines than n, the loop must stop early rather than returning
// every row.
func TestTopProcessesByCPUMac_CapsAtN(t *testing.T) {
	swapRunCmd(t, func(_ context.Context, name string, args ...string) (string, error) {
		if name != "ps" {
			t.Fatalf("unexpected command: %s %v", name, args)
		}
		return "  PID  %CPU COMMAND\n" +
			"  1   5.0 procA\n" +
			"  2   4.0 procB\n" +
			"  3   3.0 procC\n", nil
	})

	got, err := topProcessesByCPUMac(context.Background(), 2)
	if err != nil {
		t.Fatalf("topProcessesByCPUMac: %v", err)
	}
	if len(got.Rows) != 2 {
		t.Fatalf("expected n=2 to cap rows at 2, got %d: %+v", len(got.Rows), got.Rows)
	}
	if got.Rows[0][0] != "1" || got.Rows[1][0] != "2" {
		t.Errorf("expected first two rows in ps order, got %+v", got.Rows)
	}
}
