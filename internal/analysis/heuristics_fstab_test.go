package analysis

import (
	"strings"
	"testing"

	"github.com/keyorixhq/dashdiag/internal/models"
)

// A drift on a boot-critical mount (/ or /boot*) → CRIT (emergency-mode territory);
// any other drift → WARN. Clean / unverifiable → quiet.
func TestCheckFstab(t *testing.T) {
	crit := checkFstab(models.FstabInfo{Checked: true, Drifts: []models.FstabDrift{
		{Spec: "UUID=old-root", MountPoint: "/", BootMount: true},
	}})
	if len(crit) != 1 || crit[0].Level != "CRIT" {
		t.Fatalf("root drift must be CRIT, got %+v", crit)
	}
	if !strings.Contains(crit[0].Message, "/etc/fstab references UUID=old-root") {
		t.Errorf("message should name the drifting spec: %q", crit[0].Message)
	}

	warn := checkFstab(models.FstabInfo{Checked: true, Drifts: []models.FstabDrift{
		{Spec: "UUID=old-data", MountPoint: "/data"},
	}})
	if len(warn) != 1 || warn[0].Level != "WARN" {
		t.Errorf("non-boot drift must be WARN, got %+v", warn)
	}

	if got := checkFstab(models.FstabInfo{Checked: true}); len(got) != 0 {
		t.Errorf("clean fstab must be quiet, got %+v", got)
	}
	if got := checkFstab(models.FstabInfo{Checked: false}); len(got) != 0 {
		t.Errorf("unverifiable fstab must be quiet, got %+v", got)
	}
}
