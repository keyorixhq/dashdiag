package drilldown

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
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
