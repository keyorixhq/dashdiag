//go:build linux

package drilldown

import (
	"context"
	"errors"
	"os"
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

// The tests below swap the package-level lookPath/runCmd vars (see
// runcmd_helper_test.go) rather than depending on a real journalctl/host
// state, so they run deterministically regardless of what's installed.
// No t.Parallel() — see swapRunCmd's doc comment.

func TestFailedUnitLogs_EmptyUnitOrDarwin(t *testing.T) {
	if d, err := FailedUnitLogs(context.Background(), "", 20); d != nil || err != nil {
		t.Errorf("empty unit: got (%+v, %v), want (nil, nil)", d, err)
	}
}

// TestFailedUnitLogs_NoJournalctlViaSwap covers the "journalctl absent" branch
// through the swappable lookPath seam (systemd.go must use the package var,
// not a raw exec.LookPath, for this to be deterministic across environments).
func TestFailedUnitLogs_NoJournalctlViaSwap(t *testing.T) {
	swapLookPath(t, func(string) (string, error) { return "", errNotFound })
	swapRunCmd(t, func(_ context.Context, name string, args ...string) (string, error) {
		t.Fatalf("runCmd should not be called when journalctl is absent, got %s %v", name, args)
		return "", nil
	})

	d, err := FailedUnitLogs(context.Background(), "sshd.service", 20)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if d != nil {
		t.Errorf("expected nil details when journalctl is absent, got %+v", d)
	}
}

func TestFailedUnitLogs_Success(t *testing.T) {
	swapLookPath(t, func(string) (string, error) { return "/usr/bin/journalctl", nil })
	swapRunCmd(t, func(_ context.Context, name string, args ...string) (string, error) {
		if name != "journalctl" {
			t.Fatalf("unexpected command: %s %v", name, args)
		}
		return "Jul 10 00:00:00 host sshd[1]: Failed\n", nil
	})

	d, err := FailedUnitLogs(context.Background(), "sshd.service", 20)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if d == nil {
		t.Fatal("expected non-nil Details for a successful journalctl read")
	}
	if d.Type != "log_tail" || d.KV["log_tail"] == "" {
		t.Errorf("Details = %+v, want a populated log_tail KV entry", d)
	}
}

// TestFailedUnitLogs_ReadFailsAsRoot guards the "genuinely logless unit" case:
// a real root run distinguishes nothing from journalctl's stdout-only
// contract, so a failed read as root returns (nil, nil) rather than a
// permission-gap note that would wrongly suggest re-running as root.
func TestFailedUnitLogs_ReadFailsAsRoot(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("requires root — this guards the root branch specifically")
	}
	swapLookPath(t, func(string) (string, error) { return "/usr/bin/journalctl", nil })
	swapRunCmd(t, func(context.Context, string, ...string) (string, error) {
		return "", errors.New("journalctl: no entries")
	})

	d, err := FailedUnitLogs(context.Background(), "sshd.service", 20)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if d != nil {
		t.Errorf("expected nil details on a failed read as root, got %+v", d)
	}
}

// TestFailedUnitLogs_ReadFailsAsNonRoot guards the non-root caveat branch: a
// failed journalctl read must surface an honest "couldn't read the journal"
// note instead of silently implying zero log entries.
func TestFailedUnitLogs_ReadFailsAsNonRoot(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("requires non-root — this guards the non-root branch specifically")
	}
	swapLookPath(t, func(string) (string, error) { return "/usr/bin/journalctl", nil })
	swapRunCmd(t, func(context.Context, string, ...string) (string, error) {
		return "", errors.New("journalctl: permission denied")
	})

	d, err := FailedUnitLogs(context.Background(), "sshd.service", 20)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if d == nil {
		t.Fatal("expected a non-nil caveat Details for a failed non-root read")
	}
	if d.Note == "" {
		t.Error("expected a non-empty Note explaining the read failure")
	}
}
