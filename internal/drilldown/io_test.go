package drilldown

import (
	"os"
	"testing"
)

// TestReadProcIONonexistentPidIsNotPermissionError guards the partial-flag
// classification in sampleAllProcIO: a process that vanished mid-scan (a very
// common /proc race, distinct from a genuine permission-denied read) must not
// be misclassified as a permission gap — that would spuriously tell the user
// to "run as root" when the real cause is just PID churn.
func TestReadProcIONonexistentPidIsNotPermissionError(t *testing.T) {
	_, _, err := readProcIO(999999999)
	if err == nil {
		t.Skip("no unassigned-looking PID could be probed in this environment")
	}
	if os.IsPermission(err) {
		t.Errorf("a nonexistent-PID read should not be classified as a permission error, got %v", err)
	}
}
