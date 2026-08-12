package analysis

import (
	"testing"

	"github.com/keyorixhq/dashdiag/internal/models"
)

// A reachable PVE node where an INDIVIDUAL pvesh sub-query failed (storage/tasks/
// backups/HA/subscription) must report that aspect as "not verified" via INFO,
// never a silent OK — the PVE false-OK class (FALSE_OK_SWEEP #5–#8, #40). The node
// passes the APIReachable master gate (cluster status succeeded), so only the
// per-aspect flags catch these.
func TestPVEPerAspectNotVerified(t *testing.T) {
	base := models.PVEInfo{IsPVE: true, NeedsRoot: false, APIReachable: true, QuorumOK: true}

	t.Run("storage query failed", func(t *testing.T) {
		p := base
		p.TasksVerified, p.BackupVerified, p.HAVerified = true, true, true
		p.StoragesVerified = false
		if !hasInsight(checkPVE(p), "INFO", "storage health NOT verified") {
			t.Errorf("unverified storage must INFO, got %+v", checkPVE(p))
		}
	})

	t.Run("task list unreadable", func(t *testing.T) {
		p := base
		p.StoragesVerified, p.BackupVerified, p.HAVerified = true, true, true
		p.TasksVerified = false
		if !hasInsight(checkPVE(p), "INFO", "task log unreadable") {
			t.Errorf("unverified tasks must INFO, got %+v", checkPVE(p))
		}
	})

	t.Run("backup health unverified", func(t *testing.T) {
		p := base
		p.StoragesVerified, p.TasksVerified, p.HAVerified = true, true, true
		p.BackupVerified, p.BackupAgeDays, p.BackupStatuses = false, -1, nil
		if !hasInsight(checkPVE(p), "INFO", "backup health NOT verified") {
			t.Errorf("unverified backups must INFO, got %+v", checkPVE(p))
		}
	})

	t.Run("HA state unreadable", func(t *testing.T) {
		p := base
		p.StoragesVerified, p.TasksVerified, p.BackupVerified = true, true, true
		p.HAFencingOK, p.HAVerified = true, false
		if !hasInsight(checkPVE(p), "INFO", "HA fencing state could NOT be verified") {
			t.Errorf("unverified HA must INFO, got %+v", checkPVE(p))
		}
	})

	t.Run("subscription unverified does not suppress", func(t *testing.T) {
		p := base
		p.StoragesVerified, p.TasksVerified, p.BackupVerified, p.HAVerified = true, true, true, true
		p.Subscription = models.PVESubscription{Status: "unverified"}
		if !hasInsight(checkPVE(p), "INFO", "live status could NOT be verified") {
			t.Errorf("unverified subscription must INFO, got %+v", checkPVE(p))
		}
	})

	t.Run("all verified, healthy node is clean", func(t *testing.T) {
		p := base
		p.StoragesVerified, p.TasksVerified, p.BackupVerified, p.HAVerified = true, true, true, true
		p.GuestsVerified = true
		p.HAFencingOK = true
		p.BackupAgeDays = 1
		p.BackupStatuses = []models.PVEBackupStatus{{}}
		p.Subscription = models.PVESubscription{Status: "active"}
		if got := checkPVE(p); len(got) != 0 {
			t.Errorf("a fully-verified healthy node must be clean, got %+v", got)
		}
	})

	t.Run("guest enumeration failed", func(t *testing.T) {
		p := base
		p.StoragesVerified, p.TasksVerified, p.BackupVerified, p.HAVerified = true, true, true, true
		p.GuestsVerified = false
		p.HAFencingOK = true
		p.BackupAgeDays = 1
		if !hasInsight(checkPVE(p), "INFO", "guest enumeration failed") {
			t.Errorf("unverified guest enumeration must INFO, got %+v", checkPVE(p))
		}
	})
}
