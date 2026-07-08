package analysis

import (
	"strings"
	"testing"

	"github.com/keyorixhq/dashdiag/internal/models"
)

// TestCheckDisk_BusyProcessHints covers the fuser/proc-fd busy-filesystem
// check (Spec 4 addendum, §4-add): when a WARN/CRIT-usage or read-only-
// remounted filesystem carries collector-populated BusyProcesses, the insight
// must surface who is holding it open — not just the raw usage number — so an
// admin blocked by "device or resource busy" on unmount knows what to stop.
func TestCheckDisk_BusyProcessHints(t *testing.T) {
	t.Parallel()

	disk := models.DiskInfo{Filesystems: []models.FilesystemInfo{{
		Mount: "/var", Device: "/dev/sda1", FSType: "ext4", UsedPct: 95,
		BusyProcesses: []models.FSBusyProcess{
			{PID: 1234, Command: "journald", User: "root", Write: true},
			{PID: 5678, Command: "rsyslogd", User: "root", Write: false},
		},
	}}}
	insights := checkDisk(disk, defaultThresh)
	if len(insights) == 0 {
		t.Fatal("expected at least one insight for a near-full filesystem")
	}
	found := false
	for _, ins := range insights {
		if !strings.Contains(ins.Message, "disk usage") {
			continue
		}
		found = true
		if ins.Level != "CRIT" {
			t.Errorf("Level = %q, want CRIT", ins.Level)
		}
		if !strings.Contains(ins.Message, "2 process(es) have files open") {
			t.Errorf("Message = %q, want a busy-process count", ins.Message)
		}
		joined := strings.Join(ins.Hints, "\n")
		if !strings.Contains(joined, "PID 1234") || !strings.Contains(joined, "journald") {
			t.Errorf("Hints = %v, want PID 1234/journald listed", ins.Hints)
		}
		if !strings.Contains(joined, "write") {
			t.Errorf("Hints = %v, want the write-access process flagged", ins.Hints)
		}
	}
	if !found {
		t.Fatal("no disk-usage insight found")
	}
}

// TestCheckDisk_BusyProcessHints_NeedsRoot covers the honesty case: a scan
// that ran unprivileged found zero busy processes, which must not read as
// "confirmed clean" — the same false-OK-on-non-root class flagged for other
// collectors (see CLAUDE.md's privileged-collector rule).
func TestCheckDisk_BusyProcessHints_NeedsRoot(t *testing.T) {
	t.Parallel()

	disk := models.DiskInfo{Filesystems: []models.FilesystemInfo{{
		Mount: "/var", Device: "/dev/sda1", FSType: "ext4", UsedPct: 95,
		BusyCheckNeedsRoot: true,
	}}}
	insights := checkDisk(disk, defaultThresh)
	for _, ins := range insights {
		if !strings.Contains(ins.Message, "disk usage") {
			continue
		}
		joined := strings.Join(ins.Hints, "\n")
		if !strings.Contains(joined, "unprivileged") {
			t.Errorf("Hints = %v, want an unprivileged-scan caveat", ins.Hints)
		}
		return
	}
	t.Fatal("no disk-usage insight found")
}

// TestCheckDisk_BusyProcessHints_ReadOnlyRemount covers the other trigger
// condition from the spec: a read-only error remount, not just near-full usage.
func TestCheckDisk_BusyProcessHints_ReadOnlyRemount(t *testing.T) {
	t.Parallel()

	disk := models.DiskInfo{Filesystems: []models.FilesystemInfo{{
		Mount: "/data", Device: "/dev/sdb1", FSType: "xfs", UsedPct: 40, ReadOnly: true,
		BusyProcesses: []models.FSBusyProcess{{PID: 42, Command: "postgres", User: "postgres", Write: true}},
	}}}
	insights := checkDisk(disk, defaultThresh)
	found := false
	for _, ins := range insights {
		if !strings.Contains(ins.Message, "READ-ONLY") {
			continue
		}
		found = true
		joined := strings.Join(ins.Hints, "\n")
		if !strings.Contains(joined, "PID 42") || !strings.Contains(joined, "postgres") {
			t.Errorf("Hints = %v, want PID 42/postgres listed", ins.Hints)
		}
	}
	if !found {
		t.Fatal("no read-only-remount insight found")
	}
}
