package drilldown

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"testing"
	"time"
)

func writeProcIOFixture(t *testing.T, procRoot string, pid int, readBytes, writeBytes uint64) {
	t.Helper()
	dir := filepath.Join(procRoot, strconv.Itoa(pid))
	if err := os.MkdirAll(dir, 0755); err != nil {
		t.Fatalf("MkdirAll: %v", err)
	}
	content := fmt.Sprintf(
		"rchar: 0\nwchar: 0\nsyscr: 0\nsyscw: 0\nread_bytes: %d\nwrite_bytes: %d\ncancelled_write_bytes: 0\n",
		readBytes, writeBytes)
	if err := os.WriteFile(filepath.Join(dir, "io"), []byte(content), 0644); err != nil {
		t.Fatalf("WriteFile io: %v", err)
	}
}

func TestReadProcIO_HappyPath(t *testing.T) {
	t.Parallel()
	procRoot := t.TempDir()
	writeProcIOFixture(t, procRoot, 42, 4096, 8192)

	r, w, err := readProcIO(procRoot, 42)
	if err != nil {
		t.Fatalf("readProcIO: %v", err)
	}
	if r != 4096 || w != 8192 {
		t.Errorf("readProcIO() = (%d, %d), want (4096, 8192)", r, w)
	}
}

// TestTopProcessesByIOLinux_Sorting exercises the real two-sample rate
// calculation against a fixture /proc tree, mutating it mid-flight to
// simulate I/O accruing during topProcessesByIOLinuxAt's 500ms sampling gap.
func TestTopProcessesByIOLinux_Sorting(t *testing.T) {
	procRoot := t.TempDir()
	const pid = 42
	writeProcIOFixture(t, procRoot, pid, 1000, 500)
	if err := os.WriteFile(filepath.Join(procRoot, strconv.Itoa(pid), "comm"), []byte("iohog\n"), 0644); err != nil {
		t.Fatalf("WriteFile comm: %v", err)
	}

	go func() {
		time.Sleep(100 * time.Millisecond)
		// +5000 read bytes, +2500 write bytes over the 0.5s window:
		// readBps = 10000 B/s -> "9.8KB/s", writeBps = 5000 B/s -> "4.9KB/s"
		writeProcIOFixture(t, procRoot, pid, 6000, 3000)
	}()

	got, err := topProcessesByIOLinuxAt(context.Background(), 5, procRoot)
	if err != nil {
		t.Fatalf("topProcessesByIOLinuxAt: %v", err)
	}
	if len(got.Rows) != 1 {
		t.Fatalf("expected 1 row, got %d: %+v", len(got.Rows), got.Rows)
	}
	want := []string{strconv.Itoa(pid), "9.8KB/s", "4.9KB/s", "iohog"}
	for i, w := range want {
		if got.Rows[0][i] != w {
			t.Errorf("row[%d] = %q, want %q (full row: %+v)", i, got.Rows[0][i], w, got.Rows[0])
		}
	}
}

func TestTopProcessesByIOLinux_NoActivity(t *testing.T) {
	procRoot := t.TempDir()
	writeProcIOFixture(t, procRoot, 99, 1000, 500)

	got, err := topProcessesByIOLinuxAt(context.Background(), 5, procRoot)
	if err != nil {
		t.Fatalf("topProcessesByIOLinuxAt: %v", err)
	}
	if len(got.Rows) != 0 {
		t.Errorf("expected no rows when I/O counters don't change, got %+v", got.Rows)
	}
	if got.Note == "" {
		t.Error("expected a note explaining zero activity")
	}
}

// TestTopProcessesByIOLinux_NewPidMidWindowSkipped guards the "PID appeared
// mid-window" branch: a process present only in the second sample (s1) has no
// baseline in s0, so its rate cannot be computed and it must be skipped rather
// than treated as a huge (or negative) delta.
func TestTopProcessesByIOLinux_NewPidMidWindowSkipped(t *testing.T) {
	t.Parallel()
	procRoot := t.TempDir()
	writeProcIOFixture(t, procRoot, 1, 1000, 500) // present in both samples, no activity

	go func() {
		time.Sleep(50 * time.Millisecond)
		writeProcIOFixture(t, procRoot, 2, 100, 100) // new PID, appears only in s1
	}()

	got, err := topProcessesByIOLinuxAt(context.Background(), 5, procRoot)
	if err != nil {
		t.Fatalf("topProcessesByIOLinuxAt: %v", err)
	}
	for _, row := range got.Rows {
		if row[0] == "2" {
			t.Errorf("PID 2 appeared only in the second sample and should be skipped, got row %+v", row)
		}
	}
}

// TestSampleAllProcIO_PermissionDeniedSetsPartial guards the false-OK-by-
// omission classification in sampleAllProcIO: a permission-denied /proc/<pid>/io
// read (owned by another user) must flip partial=true rather than silently
// vanishing from the sample, per the same rationale as the fdlimits/swap
// analogues in this package. A directory with mode 0000 triggers EACCES for a
// non-root reader; skip gracefully if the test happens to run as root (where
// permission bits don't apply).
func TestSampleAllProcIO_PermissionDeniedSetsPartial(t *testing.T) {
	t.Parallel()
	if os.Geteuid() == 0 {
		t.Skip("running as root — permission bits don't block the read")
	}
	procRoot := t.TempDir()
	const pid = 55
	dir := filepath.Join(procRoot, strconv.Itoa(pid))
	if err := os.MkdirAll(dir, 0755); err != nil {
		t.Fatalf("MkdirAll: %v", err)
	}
	ioPath := filepath.Join(dir, "io")
	if err := os.WriteFile(ioPath, []byte("read_bytes: 0\nwrite_bytes: 0\n"), 0000); err != nil {
		t.Fatalf("WriteFile io: %v", err)
	}
	t.Cleanup(func() { _ = os.Chmod(ioPath, 0644) }) // TempDir cleanup needs read perms restored

	_, partial := sampleAllProcIO(context.Background(), procRoot)
	if !partial {
		t.Error("expected partial=true when /proc/<pid>/io is permission-denied")
	}
}

// TestTopProcessesByIOLinuxAt_ContextCancelled guards the ctx.Done() branch
// hit between the two sampling passes: a context cancelled before the 500ms
// gap elapses must return ctx.Err(), not silently proceed to a second sample.
func TestTopProcessesByIOLinuxAt_ContextCancelled(t *testing.T) {
	t.Parallel()
	procRoot := t.TempDir()
	writeProcIOFixture(t, procRoot, 1, 100, 100)

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	_, err := topProcessesByIOLinuxAt(ctx, 5, procRoot)
	if err == nil {
		t.Error("expected an error from a pre-cancelled context")
	}
}
