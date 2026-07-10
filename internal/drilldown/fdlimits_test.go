package drilldown

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"testing"
)

func writeFDFixture(t *testing.T, procRoot string, pid int, comm string, openFDs, softLimit, hardLimit int) {
	t.Helper()
	dir := filepath.Join(procRoot, strconv.Itoa(pid))
	fdDir := filepath.Join(dir, "fd")
	if err := os.MkdirAll(fdDir, 0755); err != nil {
		t.Fatalf("MkdirAll fd: %v", err)
	}
	for i := range openFDs {
		if err := os.WriteFile(filepath.Join(fdDir, strconv.Itoa(i)), nil, 0644); err != nil {
			t.Fatalf("WriteFile fd entry: %v", err)
		}
	}
	limits := fmt.Sprintf(
		"Limit                     Soft Limit           Hard Limit           Units\nMax open files            %d                 %d                 files\n",
		softLimit, hardLimit)
	if err := os.WriteFile(filepath.Join(dir, "limits"), []byte(limits), 0644); err != nil {
		t.Fatalf("WriteFile limits: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "comm"), []byte(comm+"\n"), 0644); err != nil {
		t.Fatalf("WriteFile comm: %v", err)
	}
}

func TestTopProcessesByFDLinux(t *testing.T) {
	t.Parallel()
	procRoot := t.TempDir()
	writeFDFixture(t, procRoot, 456, "myproc", 3, 10, 20)

	got, err := topProcessesByFDLinuxAt(context.Background(), 5, procRoot)
	if err != nil {
		t.Fatalf("topProcessesByFDLinuxAt: %v", err)
	}
	if len(got.Rows) != 1 {
		t.Fatalf("expected 1 row, got %d: %+v", len(got.Rows), got.Rows)
	}
	want := []string{"456", "3", "10", "30%", "myproc"}
	for i, w := range want {
		if got.Rows[0][i] != w {
			t.Errorf("row[%d] = %q, want %q (full row: %+v)", i, got.Rows[0][i], w, got.Rows[0])
		}
	}
	if got.Note != "" {
		t.Errorf("expected no partial-visibility note, got %q", got.Note)
	}
}

func TestTopProcessesByFDLinux_ZeroLimitSkipped(t *testing.T) {
	t.Parallel()
	procRoot := t.TempDir()
	writeFDFixture(t, procRoot, 789, "nolimit", 2, 0, 0)

	got, err := topProcessesByFDLinuxAt(context.Background(), 5, procRoot)
	if err != nil {
		t.Fatalf("topProcessesByFDLinuxAt: %v", err)
	}
	if len(got.Rows) != 0 {
		t.Errorf("expected process with unreadable/zero soft limit to be skipped, got %+v", got.Rows)
	}
}

// TestTopProcessesByFDLinux_PermissionDeniedSetsPartial guards the false-OK-
// by-omission classification: a permission-denied /proc/<pid>/fd read (owned
// by another user) must flip the partial flag and surface an honest Note
// rather than silently vanishing from the ranking. A directory with mode 0000
// triggers EACCES for a non-root reader.
func TestTopProcessesByFDLinux_PermissionDeniedSetsPartial(t *testing.T) {
	t.Parallel()
	if os.Geteuid() == 0 {
		t.Skip("running as root — permission bits don't block the read")
	}
	procRoot := t.TempDir()
	const pid = 222
	dir := filepath.Join(procRoot, strconv.Itoa(pid))
	fdDir := filepath.Join(dir, "fd")
	if err := os.MkdirAll(dir, 0755); err != nil {
		t.Fatalf("MkdirAll: %v", err)
	}
	if err := os.Mkdir(fdDir, 0000); err != nil {
		t.Fatalf("Mkdir fd: %v", err)
	}
	t.Cleanup(func() { _ = os.Chmod(fdDir, 0755) }) // TempDir cleanup needs read perms restored

	got, err := topProcessesByFDLinuxAt(context.Background(), 5, procRoot)
	if err != nil {
		t.Fatalf("topProcessesByFDLinuxAt: %v", err)
	}
	if len(got.Rows) != 0 {
		t.Errorf("expected the permission-denied process to be excluded from rows, got %+v", got.Rows)
	}
	if got.Note == "" {
		t.Error("expected a partial-visibility note when /proc/<pid>/fd is permission-denied")
	}
}

// TestTopProcessesByFDLinuxAt_WalkProcsErrorPropagates guards the early-return
// branch: when walkProcs itself fails (procRoot doesn't exist, so its initial
// os.ReadDir errors before any entries are gathered) and zero entries were
// collected, the error must propagate rather than be swallowed into an empty
// result — an empty *models.Details there would read as "no FD-heavy
// processes" instead of "couldn't read /proc at all".
func TestTopProcessesByFDLinuxAt_WalkProcsErrorPropagates(t *testing.T) {
	t.Parallel()
	missing := filepath.Join(t.TempDir(), "does-not-exist")

	_, err := topProcessesByFDLinuxAt(context.Background(), 5, missing)
	if err == nil {
		t.Error("expected an error when procRoot itself cannot be read")
	}
}

// TestTopProcessesByFDLinux_TruncatesToN guards the len(entries) > n cap:
// more FD-heavy processes than requested must be truncated to the top n by
// used%, not merely sorted.
func TestTopProcessesByFDLinux_TruncatesToN(t *testing.T) {
	t.Parallel()
	procRoot := t.TempDir()
	writeFDFixture(t, procRoot, 1, "a", 1, 10, 20) // 10%
	writeFDFixture(t, procRoot, 2, "b", 5, 10, 20) // 50%
	writeFDFixture(t, procRoot, 3, "c", 9, 10, 20) // 90% (busiest)

	got, err := topProcessesByFDLinuxAt(context.Background(), 2, procRoot)
	if err != nil {
		t.Fatalf("topProcessesByFDLinuxAt: %v", err)
	}
	if len(got.Rows) != 2 {
		t.Fatalf("expected n=2 to cap rows at 2, got %d: %+v", len(got.Rows), got.Rows)
	}
	if got.Rows[0][0] != "3" {
		t.Errorf("expected pid 3 (highest used%%) first, got %+v", got.Rows)
	}
}

func TestFDSoftLimit(t *testing.T) {
	t.Parallel()
	procRoot := t.TempDir()
	writeFDFixture(t, procRoot, 111, "p", 0, 1024, 4096)

	if got := fdSoftLimit(procRoot, 111); got != 1024 {
		t.Errorf("fdSoftLimit() = %d, want 1024", got)
	}
}

func TestFDSoftLimit_MissingProcess(t *testing.T) {
	t.Parallel()
	if got := fdSoftLimit(t.TempDir(), 999); got != 0 {
		t.Errorf("fdSoftLimit() for nonexistent PID = %d, want 0", got)
	}
}

// TestFDSoftLimit_MalformedOpenFilesLineSkipped guards the len(fields) < 4
// defensive skip: a truncated "open files" line must fall through to the
// default 0 rather than index out of range.
func TestFDSoftLimit_MalformedOpenFilesLineSkipped(t *testing.T) {
	t.Parallel()
	procRoot := t.TempDir()
	const pid = 321
	dir := filepath.Join(procRoot, strconv.Itoa(pid))
	if err := os.MkdirAll(dir, 0755); err != nil {
		t.Fatalf("MkdirAll: %v", err)
	}
	content := "Limit  Soft Limit  Hard Limit  Units\nMax open files\n"
	if err := os.WriteFile(filepath.Join(dir, "limits"), []byte(content), 0644); err != nil {
		t.Fatalf("WriteFile limits: %v", err)
	}

	if got := fdSoftLimit(procRoot, pid); got != 0 {
		t.Errorf("fdSoftLimit() for a malformed open-files line = %d, want 0", got)
	}
}

// TestTopProcessesByFDPercent_RealProc exercises the exported dispatcher and
// its Linux hardcoded-"/proc" wrapper against the ACTUAL /proc of the test
// container (real, uncancelled context) — see the equivalent comment on
// TestTopProcessesByCPU_RealProc in cpu_test.go for why this is safe and
// deterministic here. Exact values are already covered by *LinuxAt above.
func TestTopProcessesByFDPercent_RealProc(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("exercises the Linux /proc-backed path; the macOS dispatch (open file count) is covered by its own mocked *Mac test")
	}
	got, err := TopProcessesByFDPercent(context.Background(), 5)
	if err != nil {
		t.Fatalf("TopProcessesByFDPercent: %v", err)
	}
	if got == nil {
		t.Fatal("expected non-nil Details from a real /proc read")
	}
	if got.Type != "process_table" || got.Title != "Top processes by FD usage" {
		t.Errorf("unexpected shape: %+v", got)
	}
	if len(got.Rows) > 5 {
		t.Errorf("expected at most 5 rows, got %d", len(got.Rows))
	}
}

// topProcessesByFDMac is only invoked at runtime on darwin, but it's a plain
// function, callable directly on any host — mocking runCmd lets it be
// exercised on Linux CI too. It shells out twice (lsof once, then ps per
// distinct PID), so the mock dispatches on command name. No t.Parallel(): see
// swapRunCmd's doc comment.
func TestTopProcessesByFDMac(t *testing.T) {
	swapRunCmd(t, func(_ context.Context, name string, args ...string) (string, error) {
		switch name {
		case "lsof":
			return "p123\nn/dev/null\nn/dev/null\nn/tmp/foo\np456\nn/dev/null\n", nil
		case "ps":
			pid := args[1]
			switch pid {
			case "123":
				return "myproc\n", nil
			case "456":
				return "otherproc\n", nil
			default:
				t.Fatalf("unexpected ps -p %s", pid)
			}
		default:
			t.Fatalf("unexpected command: %s %v", name, args)
		}
		return "", nil
	})

	got, err := topProcessesByFDMac(context.Background(), 5)
	if err != nil {
		t.Fatalf("topProcessesByFDMac: %v", err)
	}
	if len(got.Rows) != 2 {
		t.Fatalf("expected 2 rows, got %d: %+v", len(got.Rows), got.Rows)
	}
	want := [][]string{
		{"123", "3", "myproc"},
		{"456", "1", "otherproc"},
	}
	for i, w := range want {
		for j, v := range w {
			if got.Rows[i][j] != v {
				t.Errorf("row[%d][%d] = %q, want %q (full rows: %+v)", i, j, got.Rows[i][j], v, got.Rows)
			}
		}
	}
}
