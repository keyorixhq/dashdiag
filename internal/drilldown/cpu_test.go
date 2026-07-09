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
