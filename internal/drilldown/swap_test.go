package drilldown

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"testing"
)

func writeSwapStatusFixture(t *testing.T, procRoot string, pid int, name string, swapKB int) {
	t.Helper()
	dir := filepath.Join(procRoot, strconv.Itoa(pid))
	if err := os.MkdirAll(dir, 0755); err != nil {
		t.Fatalf("MkdirAll: %v", err)
	}
	content := fmt.Sprintf("Name:\t%s\nVmSwap:\t   %d kB\n", name, swapKB)
	if err := os.WriteFile(filepath.Join(dir, "status"), []byte(content), 0644); err != nil {
		t.Fatalf("WriteFile status: %v", err)
	}
}

func TestTopProcessesBySwapLinux(t *testing.T) {
	t.Parallel()
	procRoot := t.TempDir()
	writeSwapStatusFixture(t, procRoot, 789, "swappy", 2048)

	got, err := topProcessesBySwapLinuxAt(context.Background(), 5, procRoot)
	if err != nil {
		t.Fatalf("topProcessesBySwapLinuxAt: %v", err)
	}
	if len(got.Rows) != 1 {
		t.Fatalf("expected 1 row, got %d: %+v", len(got.Rows), got.Rows)
	}
	want := []string{"789", "2.0MB", "swappy"}
	for i, w := range want {
		if got.Rows[0][i] != w {
			t.Errorf("row[%d] = %q, want %q (full row: %+v)", i, got.Rows[0][i], w, got.Rows[0])
		}
	}
}

func TestTopProcessesBySwapLinux_ZeroSwapExcluded(t *testing.T) {
	t.Parallel()
	procRoot := t.TempDir()
	writeSwapStatusFixture(t, procRoot, 111, "noswap", 0)

	got, err := topProcessesBySwapLinuxAt(context.Background(), 5, procRoot)
	if err != nil {
		t.Fatalf("topProcessesBySwapLinuxAt: %v", err)
	}
	if len(got.Rows) != 0 {
		t.Errorf("expected process with zero swap to be excluded, got %+v", got.Rows)
	}
}

func TestTopProcessesBySwapLinux_SortedDescending(t *testing.T) {
	t.Parallel()
	procRoot := t.TempDir()
	writeSwapStatusFixture(t, procRoot, 1, "small", 100)
	writeSwapStatusFixture(t, procRoot, 2, "big", 5000)

	got, err := topProcessesBySwapLinuxAt(context.Background(), 5, procRoot)
	if err != nil {
		t.Fatalf("topProcessesBySwapLinuxAt: %v", err)
	}
	if len(got.Rows) != 2 {
		t.Fatalf("expected 2 rows, got %d: %+v", len(got.Rows), got.Rows)
	}
	if got.Rows[0][2] != "big" || got.Rows[1][2] != "small" {
		t.Errorf("expected rows sorted by swap descending (big, small), got %+v", got.Rows)
	}
}

func TestTopProcessesBySwapLinux_LimitN(t *testing.T) {
	t.Parallel()
	procRoot := t.TempDir()
	writeSwapStatusFixture(t, procRoot, 1, "a", 100)
	writeSwapStatusFixture(t, procRoot, 2, "b", 200)
	writeSwapStatusFixture(t, procRoot, 3, "c", 300)

	got, err := topProcessesBySwapLinuxAt(context.Background(), 2, procRoot)
	if err != nil {
		t.Fatalf("topProcessesBySwapLinuxAt: %v", err)
	}
	if len(got.Rows) != 2 {
		t.Errorf("expected n=2 to cap rows at 2, got %d: %+v", len(got.Rows), got.Rows)
	}
}

// TestTopProcessesBySwap_RealProc exercises the exported dispatcher and its
// Linux hardcoded-"/proc" wrapper against the ACTUAL /proc of the test
// container (real, uncancelled context) — see the equivalent comment on
// TestTopProcessesByCPU_RealProc in cpu_test.go for why this is safe and
// deterministic here. Most containers have zero swap usage, so this only
// asserts "no panic, no error, plausible shape" — exact values are already
// covered by *LinuxAt above.
func TestTopProcessesBySwap_RealProc(t *testing.T) {
	got, err := TopProcessesBySwap(context.Background(), 5)
	if err != nil {
		t.Fatalf("TopProcessesBySwap: %v", err)
	}
	if got == nil {
		t.Fatal("expected non-nil Details from a real /proc read")
	}
	if got.Type != "process_table" || got.Title != "Top processes by swap usage" {
		t.Errorf("unexpected shape: %+v", got)
	}
	if len(got.Rows) > 5 {
		t.Errorf("expected at most 5 rows, got %d", len(got.Rows))
	}
}
