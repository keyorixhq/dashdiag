package drilldown

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"testing"
)

func writeProcessStatFixture(t *testing.T, procRoot string, pid int, comm, state string, ppid int) {
	t.Helper()
	dir := filepath.Join(procRoot, strconv.Itoa(pid))
	if err := os.MkdirAll(dir, 0755); err != nil {
		t.Fatalf("MkdirAll: %v", err)
	}
	line := fmt.Sprintf("%d (%s) %s %d 0 0 0 0 0 0 0 0 0 0 0\n", pid, comm, state, ppid)
	if err := os.WriteFile(filepath.Join(dir, "stat"), []byte(line), 0644); err != nil {
		t.Fatalf("WriteFile stat: %v", err)
	}
}

func writeProcessCommFixture(t *testing.T, procRoot string, pid int, comm string) {
	t.Helper()
	dir := filepath.Join(procRoot, strconv.Itoa(pid))
	if err := os.MkdirAll(dir, 0755); err != nil {
		t.Fatalf("MkdirAll: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "comm"), []byte(comm+"\n"), 0644); err != nil {
		t.Fatalf("WriteFile comm: %v", err)
	}
}

func TestHungProcessesLinux(t *testing.T) {
	t.Parallel()
	procRoot := t.TempDir()
	writeProcessStatFixture(t, procRoot, 100, "stuckproc", "D", 1)
	writeProcessCommFixture(t, procRoot, 1, "init")

	got, err := hungProcessesLinuxAt(context.Background(), procRoot)
	if err != nil {
		t.Fatalf("hungProcessesLinuxAt: %v", err)
	}
	if len(got.Rows) != 1 {
		t.Fatalf("expected 1 row, got %d: %+v", len(got.Rows), got.Rows)
	}
	want := []string{"100", "stuckproc", "1", "init"}
	for i, w := range want {
		if got.Rows[0][i] != w {
			t.Errorf("row[%d] = %q, want %q (full row: %+v)", i, got.Rows[0][i], w, got.Rows[0])
		}
	}
}

// TestHungProcessesLinuxAt_MalformedStatSkipped guards the !ok || len(rest) <
// 2 skip: a /proc/<pid>/stat with no closing paren for comm (unparseable) and
// one with too few trailing fields must both be ignored rather than
// panicking on an out-of-range index.
func TestHungProcessesLinuxAt_MalformedStatSkipped(t *testing.T) {
	t.Parallel()
	procRoot := t.TempDir()
	unparseable := filepath.Join(procRoot, "101")
	if err := os.MkdirAll(unparseable, 0755); err != nil {
		t.Fatalf("MkdirAll: %v", err)
	}
	if err := os.WriteFile(filepath.Join(unparseable, "stat"), []byte("101 (noclosingparen D 1\n"), 0644); err != nil {
		t.Fatalf("WriteFile stat: %v", err)
	}
	tooShort := filepath.Join(procRoot, "102")
	if err := os.MkdirAll(tooShort, 0755); err != nil {
		t.Fatalf("MkdirAll: %v", err)
	}
	if err := os.WriteFile(filepath.Join(tooShort, "stat"), []byte("102 (short) D\n"), 0644); err != nil {
		t.Fatalf("WriteFile stat: %v", err)
	}

	got, err := hungProcessesLinuxAt(context.Background(), procRoot)
	if err != nil {
		t.Fatalf("hungProcessesLinuxAt: %v", err)
	}
	if len(got.Rows) != 0 {
		t.Errorf("expected both malformed stat entries to be skipped, got %+v", got.Rows)
	}
}

// TestHungProcessesLinuxAt_WalkProcsErrorPropagates guards the early-return
// branch: when walkProcs itself fails (procRoot doesn't exist) and zero
// entries were collected, the error must propagate rather than be swallowed
// into an empty "no hung processes" result.
func TestHungProcessesLinuxAt_WalkProcsErrorPropagates(t *testing.T) {
	t.Parallel()
	missing := filepath.Join(t.TempDir(), "does-not-exist")

	_, err := hungProcessesLinuxAt(context.Background(), missing)
	if err == nil {
		t.Error("expected an error when procRoot itself cannot be read")
	}
}

func TestHungProcessesLinux_NoneHung(t *testing.T) {
	t.Parallel()
	procRoot := t.TempDir()
	writeProcessStatFixture(t, procRoot, 200, "runningproc", "R", 1)

	got, err := hungProcessesLinuxAt(context.Background(), procRoot)
	if err != nil {
		t.Fatalf("hungProcessesLinuxAt: %v", err)
	}
	if got.Type != "kv_table" {
		t.Errorf("expected kv_table fallback with no D-state processes, got Type=%q Rows=%+v", got.Type, got.Rows)
	}
	if got.Note == "" {
		t.Error("expected a note explaining no hung processes were found")
	}
}

func TestZombiesWithParentLinux(t *testing.T) {
	t.Parallel()
	procRoot := t.TempDir()
	writeProcessStatFixture(t, procRoot, 300, "deadproc", "Z", 50)
	writeProcessCommFixture(t, procRoot, 50, "systemd")

	got, err := zombiesWithParentLinuxAt(context.Background(), procRoot)
	if err != nil {
		t.Fatalf("zombiesWithParentLinuxAt: %v", err)
	}
	if len(got.Rows) != 1 {
		t.Fatalf("expected 1 row, got %d: %+v", len(got.Rows), got.Rows)
	}
	want := []string{"300", "deadproc", "50", "systemd"}
	for i, w := range want {
		if got.Rows[0][i] != w {
			t.Errorf("row[%d] = %q, want %q (full row: %+v)", i, got.Rows[0][i], w, got.Rows[0])
		}
	}
}

// TestZombiesWithParentLinuxAt_MalformedStatSkipped guards the !ok ||
// len(rest) < 2 skip in the zombie scanner (same shape as the hung-processes
// equivalent): an unparseable stat line must be ignored, not crash the scan.
func TestZombiesWithParentLinuxAt_MalformedStatSkipped(t *testing.T) {
	t.Parallel()
	procRoot := t.TempDir()
	unparseable := filepath.Join(procRoot, "301")
	if err := os.MkdirAll(unparseable, 0755); err != nil {
		t.Fatalf("MkdirAll: %v", err)
	}
	if err := os.WriteFile(filepath.Join(unparseable, "stat"), []byte("301 (noclosingparen Z 1\n"), 0644); err != nil {
		t.Fatalf("WriteFile stat: %v", err)
	}

	got, err := zombiesWithParentLinuxAt(context.Background(), procRoot)
	if err != nil {
		t.Fatalf("zombiesWithParentLinuxAt: %v", err)
	}
	if len(got.Rows) != 0 {
		t.Errorf("expected the malformed stat entry to be skipped, got %+v", got.Rows)
	}
}

// TestZombiesWithParentLinuxAt_WalkProcsErrorPropagates guards the
// early-return branch: when walkProcs itself fails (procRoot doesn't exist)
// and zero entries were collected, the error must propagate.
func TestZombiesWithParentLinuxAt_WalkProcsErrorPropagates(t *testing.T) {
	t.Parallel()
	missing := filepath.Join(t.TempDir(), "does-not-exist")

	_, err := zombiesWithParentLinuxAt(context.Background(), missing)
	if err == nil {
		t.Error("expected an error when procRoot itself cannot be read")
	}
}

// zombiesWithParentMac is only invoked at runtime on darwin, but it's a plain
// function, callable directly on any host — mocking runCmd lets it be
// exercised on Linux CI too. No t.Parallel(): see swapRunCmd's doc comment.
func TestZombiesWithParentMac(t *testing.T) {
	swapRunCmd(t, func(_ context.Context, name string, args ...string) (string, error) {
		if name != "ps" {
			t.Fatalf("unexpected command: %s %v", name, args)
		}
		return "  PID STAT PPID COMM\n    1    Ss    0 launchd\n  200    Z     1 deadproc\n", nil
	})

	got, err := zombiesWithParentMac(context.Background())
	if err != nil {
		t.Fatalf("zombiesWithParentMac: %v", err)
	}
	if len(got.Rows) != 1 {
		t.Fatalf("expected 1 row, got %d: %+v", len(got.Rows), got.Rows)
	}
	want := []string{"200", "deadproc", "1", "launchd"}
	for i, w := range want {
		if got.Rows[0][i] != w {
			t.Errorf("row[%d] = %q, want %q (full row: %+v)", i, got.Rows[0][i], w, got.Rows[0])
		}
	}
}

// TestZombiesWithParentMac_ShortLineSkippedInBothPasses guards the
// len(fields) < 4 skip, which appears twice: once while building the
// pid->comm index, once while scanning for zombies. A truncated line must be
// ignored in both passes rather than causing an out-of-range panic.
func TestZombiesWithParentMac_ShortLineSkippedInBothPasses(t *testing.T) {
	swapRunCmd(t, func(_ context.Context, name string, args ...string) (string, error) {
		if name != "ps" {
			t.Fatalf("unexpected command: %s %v", name, args)
		}
		return "  PID STAT PPID COMM\n" +
			"  1\n" + // too few fields — skipped in both passes
			"  1    Ss    0 launchd\n" +
			"  200    Z     1 deadproc\n", nil
	})

	got, err := zombiesWithParentMac(context.Background())
	if err != nil {
		t.Fatalf("zombiesWithParentMac: %v", err)
	}
	if len(got.Rows) != 1 || got.Rows[0][0] != "200" || got.Rows[0][3] != "launchd" {
		t.Errorf("expected the truncated line skipped and the real zombie resolved, got %+v", got.Rows)
	}
}

// TestZombiesWithParentMac_RunCmdError guards the error-propagation branch: a
// failing `ps` invocation must surface the error rather than a partial or
// empty result.
func TestZombiesWithParentMac_RunCmdError(t *testing.T) {
	swapRunCmd(t, func(context.Context, string, ...string) (string, error) {
		return "", errNotFound
	})

	_, err := zombiesWithParentMac(context.Background())
	if err == nil {
		t.Error("expected an error when ps fails")
	}
}

// TestZombiesWithParentMac_UnknownParentFallsBackToQuestionMark guards the
// parentCmd == "" -> "?" fallback: a zombie whose ppid isn't present in the
// pid->comm index (parent already reaped) must render "?" rather than an
// empty cell.
func TestZombiesWithParentMac_UnknownParentFallsBackToQuestionMark(t *testing.T) {
	swapRunCmd(t, func(_ context.Context, name string, args ...string) (string, error) {
		if name != "ps" {
			t.Fatalf("unexpected command: %s %v", name, args)
		}
		// ppid 999 has no corresponding row in the listing.
		return "  PID STAT PPID COMM\n  200    Z   999 deadproc\n", nil
	})

	got, err := zombiesWithParentMac(context.Background())
	if err != nil {
		t.Fatalf("zombiesWithParentMac: %v", err)
	}
	if len(got.Rows) != 1 || got.Rows[0][3] != "?" {
		t.Errorf("expected parent cmd \"?\" for an unresolvable ppid, got %+v", got.Rows)
	}
}

// TestHungProcesses_RealProc exercises the exported dispatcher and its Linux
// hardcoded-"/proc" wrapper against the ACTUAL /proc of the test container
// (real, uncancelled context) — see the equivalent comment on
// TestTopProcessesByCPU_RealProc in cpu_test.go for why this is safe and
// deterministic here. The container's process table almost never has a D
// (uninterruptible sleep) process, so this only asserts "no panic, no error,
// plausible shape" — exact values are already covered by
// hungProcessesLinuxAt above (both the found and not-found branches).
func TestHungProcesses_RealProc(t *testing.T) {
	got, err := HungProcesses(context.Background())
	if err != nil {
		t.Fatalf("HungProcesses: %v", err)
	}
	if got == nil {
		t.Fatal("expected non-nil Details from a real /proc read")
	}
	if got.Type != "process_table" && got.Type != "kv_table" {
		t.Errorf("unexpected Type: %q (full: %+v)", got.Type, got)
	}
}

// TestZombiesWithParent_RealProc exercises the exported dispatcher and its
// Linux hardcoded-"/proc" wrapper (zombiesWithParentLinux) against the ACTUAL
// /proc of the test container (real, uncancelled context) — same rationale as
// TestHungProcesses_RealProc above. Exact values are already covered by
// zombiesWithParentLinuxAt above.
func TestZombiesWithParent_RealProc(t *testing.T) {
	got, err := ZombiesWithParent(context.Background())
	if err != nil {
		t.Fatalf("ZombiesWithParent: %v", err)
	}
	if got == nil {
		t.Fatal("expected non-nil Details from a real /proc read")
	}
	if got.Type != "process_table" {
		t.Errorf("unexpected Type: %q (full: %+v)", got.Type, got)
	}
}

func TestZombiesWithParentLinux_NoZombies(t *testing.T) {
	t.Parallel()
	procRoot := t.TempDir()
	writeProcessStatFixture(t, procRoot, 400, "sleepingproc", "S", 1)

	got, err := zombiesWithParentLinuxAt(context.Background(), procRoot)
	if err != nil {
		t.Fatalf("zombiesWithParentLinuxAt: %v", err)
	}
	if len(got.Rows) != 0 {
		t.Errorf("expected no zombie rows, got %+v", got.Rows)
	}
}
