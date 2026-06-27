package analysis

import (
	"strings"
	"testing"

	"github.com/keyorixhq/dashdiag/internal/models"
)

// `systemctl is-system-running` == "maintenance" means the host booted into
// rescue/emergency mode (e.g. a root-fs fsck failure) rather than its default
// target — a CRIT. The Dell VxRail / cloned-appliance fingerprint.
func TestCheckSystemdEmergencyMode(t *testing.T) {
	got := checkSystemd(models.SystemdInfo{Available: true, SystemState: "maintenance"})
	if !hasInsight(got, "CRIT", "emergency/rescue mode") {
		t.Fatalf("maintenance state must CRIT on emergency mode, got %+v", got)
	}
}

// "degraded" (a failed unit on an otherwise-normal boot) must NOT trip the
// emergency-mode CRIT — that's covered by the per-unit checks, and degraded is
// noisy (it includes units dsd deliberately filters). No double-fire.
func TestCheckSystemdDegradedNotEmergency(t *testing.T) {
	got := checkSystemd(models.SystemdInfo{Available: true, SystemState: "degraded"})
	for _, ins := range got {
		if ins.Level == "CRIT" {
			t.Errorf("degraded state must not emit a CRIT here, got %q", ins.Message)
		}
	}
	// running is likewise quiet.
	if got := checkSystemd(models.SystemdInfo{Available: true, SystemState: "running"}); len(got) != 0 {
		t.Errorf("running state must be quiet, got %+v", got)
	}
}

// A failed boot-filesystem unit (fsck/remount) gets a targeted repair hint
// (e2fsck / blkid / fstab), not the generic "unit failed" message.
func TestCheckSystemdFsckUnitFailure(t *testing.T) {
	got := checkSystemd(models.SystemdInfo{
		Available:   true,
		FailedUnits: []string{"systemd-fsck-root.service"},
	})
	if !hasInsight(got, "CRIT", "boot filesystem unit") {
		t.Fatalf("fsck unit failure should get the targeted boot-fs message, got %+v", got)
	}
	var found bool
	for _, ins := range got {
		for _, h := range ins.Hints {
			if strings.Contains(h, "e2fsck") {
				found = true
			}
		}
	}
	if !found {
		t.Error("fsck failure hint should mention e2fsck repair")
	}
}
