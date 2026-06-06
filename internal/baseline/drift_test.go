package baseline

import (
	"testing"

	"github.com/keyorixhq/dashdiag/internal/models"
)

// Tests for the pure drift-detection logic: security-baseline diffing (new SUID
// binaries, sudo NOPASSWD, suspect crons) and sysctl golden-drift. The SSH-hash
// comparison path reads /etc/ssh and is intentionally not asserted here.

func TestToSet(t *testing.T) {
	s := toSet([]string{"a", "b", "a"})
	if !s["a"] || !s["b"] || len(s) != 2 {
		t.Errorf("toSet = %v", s)
	}
	if len(toSet(nil)) != 0 {
		t.Error("toSet(nil) should be empty")
	}
}

func TestDiffSecurityBaseline(t *testing.T) {
	base := &SecurityBaseline{
		KnownSUIDs:   []string{"/usr/bin/sudo", "/usr/bin/passwd"},
		SudoNopasswd: []string{"deploy"},
		SuspectCrons: nil,
		// nil SSHConfigHashes → the SSH-drift loop is a no-op (deterministic).
	}

	t.Run("nil baseline reports NoBaseline", func(t *testing.T) {
		d := DiffSecurityBaseline(nil, &models.SecurityInfo{})
		if !d.NoBaseline {
			t.Error("nil baseline should set NoBaseline")
		}
	})

	t.Run("new SUID detected", func(t *testing.T) {
		cur := &models.SecurityInfo{SUIDBinaries: []string{"/usr/bin/sudo", "/usr/bin/passwd", "/usr/local/bin/evil"}}
		d := DiffSecurityBaseline(base, cur)
		if len(d.NewSUIDs) != 1 || d.NewSUIDs[0] != "/usr/local/bin/evil" {
			t.Errorf("NewSUIDs = %v, want [/usr/local/bin/evil]", d.NewSUIDs)
		}
		if !d.HasChanges() {
			t.Error("a new SUID should count as a change")
		}
	})

	t.Run("removed SUID detected (not a change)", func(t *testing.T) {
		cur := &models.SecurityInfo{SUIDBinaries: []string{"/usr/bin/sudo"}}
		d := DiffSecurityBaseline(base, cur)
		if len(d.RemovedSUIDs) != 1 || d.RemovedSUIDs[0] != "/usr/bin/passwd" {
			t.Errorf("RemovedSUIDs = %v", d.RemovedSUIDs)
		}
		if d.HasChanges() {
			t.Error("a removed SUID alone is informational, not a change")
		}
	})

	t.Run("new sudo NOPASSWD detected", func(t *testing.T) {
		cur := &models.SecurityInfo{SudoNopasswd: []string{"deploy", "ops"}}
		d := DiffSecurityBaseline(base, cur)
		if len(d.NewSudoEntries) != 1 || d.NewSudoEntries[0] != "ops" {
			t.Errorf("NewSudoEntries = %v", d.NewSudoEntries)
		}
	})

	t.Run("new suspect cron detected", func(t *testing.T) {
		cur := &models.SecurityInfo{SuspectCrons: []string{"/etc/cron.d/miner"}}
		d := DiffSecurityBaseline(base, cur)
		if len(d.NewCronEntries) != 1 {
			t.Errorf("NewCronEntries = %v", d.NewCronEntries)
		}
	})

	t.Run("no change when current matches baseline", func(t *testing.T) {
		cur := &models.SecurityInfo{
			SUIDBinaries: []string{"/usr/bin/sudo", "/usr/bin/passwd"},
			SudoNopasswd: []string{"deploy"},
		}
		d := DiffSecurityBaseline(base, cur)
		if d.HasChanges() {
			t.Errorf("identical state should report no changes: %+v", d)
		}
	})
}

func TestComputeSysctlDrift(t *testing.T) {
	mk := func(s models.SysctlInfo) *Snapshot {
		return &Snapshot{Checks: []CheckResult{{Name: "Sysctl", Raw: s}}}
	}
	golden := mk(models.SysctlInfo{VMSwappiness: 10, NetSomaxconn: 4096})
	current := mk(models.SysctlInfo{VMSwappiness: 60, NetSomaxconn: 4096})

	drift := ComputeSysctlDrift(golden, current)
	if len(drift) != 1 {
		t.Fatalf("expected 1 drifted param, got %+v", drift)
	}
	if drift[0].Param != "vm_swappiness" || drift[0].Before != 10 || drift[0].After != 60 {
		t.Errorf("drift = %+v, want vm_swappiness 10->60", drift[0])
	}

	// Identical snapshots → no drift.
	if d := ComputeSysctlDrift(golden, golden); len(d) != 0 {
		t.Errorf("identical snapshots should not drift, got %+v", d)
	}
	// A snapshot without a Sysctl check yields nil raw → no drift.
	empty := &Snapshot{}
	if d := ComputeSysctlDrift(empty, current); d != nil {
		t.Errorf("missing Sysctl check should yield nil drift, got %+v", d)
	}
}
