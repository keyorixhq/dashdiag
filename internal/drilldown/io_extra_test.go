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
