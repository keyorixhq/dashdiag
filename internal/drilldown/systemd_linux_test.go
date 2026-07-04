//go:build linux

package drilldown

import (
	"context"
	"os/exec"
	"testing"
)

// TestFailedUnitLogsNoJournalctl guards the "no journald on this host" case:
// when journalctl isn't installed, FailedUnitLogs must return (nil, nil) —
// nothing to report — rather than fabricating a permission-gap note that
// would wrongly suggest running as root would help.
func TestFailedUnitLogsNoJournalctl(t *testing.T) {
	if _, err := exec.LookPath("journalctl"); err == nil {
		t.Skip("journalctl is installed in this environment; this test targets hosts without it")
	}
	d, err := FailedUnitLogs(context.Background(), "sshd.service", 20)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if d != nil {
		t.Errorf("expected nil details when journalctl is absent, got %+v", d)
	}
}
