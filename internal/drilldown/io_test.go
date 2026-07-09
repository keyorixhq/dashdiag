package drilldown

import (
	"context"
	"os"
	"testing"
)

// TestReadProcIONonexistentPidIsNotPermissionError guards the partial-flag
// classification in sampleAllProcIO: a process that vanished mid-scan (a very
// common /proc race, distinct from a genuine permission-denied read) must not
// be misclassified as a permission gap — that would spuriously tell the user
// to "run as root" when the real cause is just PID churn.
func TestReadProcIONonexistentPidIsNotPermissionError(t *testing.T) {
	_, _, err := readProcIO("/proc", 999999999)
	if err == nil {
		t.Skip("no unassigned-looking PID could be probed in this environment")
	}
	if os.IsPermission(err) {
		t.Errorf("a nonexistent-PID read should not be classified as a permission error, got %v", err)
	}
}

// TestTopProcessesByIO_RealProc exercises the exported dispatcher and its
// Linux hardcoded-"/proc" wrapper against the ACTUAL /proc of the test
// container (real, uncancelled context) — see the equivalent comment on
// TestTopProcessesByCPU_RealProc in cpu_test.go for why this is safe and
// deterministic here. Exact values are already covered by *LinuxAt in
// io_extra_test.go.
func TestTopProcessesByIO_RealProc(t *testing.T) {
	got, err := TopProcessesByIO(context.Background(), 5)
	if err != nil {
		t.Fatalf("TopProcessesByIO: %v", err)
	}
	if got == nil {
		t.Fatal("expected non-nil Details from a real /proc read")
	}
	if got.Type != "process_table" || got.Title != "Top processes by I/O" {
		t.Errorf("unexpected shape: %+v", got)
	}
	if len(got.Rows) > 5 {
		t.Errorf("expected at most 5 rows, got %d", len(got.Rows))
	}
}
