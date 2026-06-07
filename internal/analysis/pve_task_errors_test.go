package analysis

import (
	"strings"
	"testing"

	"github.com/keyorixhq/dashdiag/internal/models"
)

// Recent failed Proxmox tasks (migrations/snapshots/restores) were collected but
// never surfaced. Backups (vzdump) are excluded — covered by checkPVEBackups.
func TestCheckPVETaskErrors(t *testing.T) {
	if got := checkPVETaskErrors(models.PVEInfo{}); got != nil {
		t.Errorf("no task errors should yield nil, got %v", got)
	}

	onlyBackups := models.PVEInfo{TaskErrors: []models.PVETaskError{{Type: "vzdump"}, {Type: "vzdump"}}}
	if got := checkPVETaskErrors(onlyBackups); got != nil {
		t.Errorf("vzdump-only should be excluded (handled by backups check), got %v", got)
	}

	mixed := models.PVEInfo{TaskErrors: []models.PVETaskError{
		{Type: "vzdump"}, // excluded
		{Type: "qmigrate"},
		{Type: "vzsnapshot"},
		{Type: "qmigrate"}, // duplicate type — counted, listed once
	}}
	got := checkPVETaskErrors(mixed)
	if len(got) != 1 || got[0].Level != "WARN" || got[0].Check != "PVE" {
		t.Fatalf("mixed -> %+v, want one WARN on PVE", got)
	}
	msg := got[0].Message
	if !strings.Contains(msg, "3 Proxmox task") { // qmigrate x2 + vzsnapshot
		t.Errorf("want 3 non-backup failures, got %q", msg)
	}
	if !strings.Contains(msg, "qmigrate") || !strings.Contains(msg, "vzsnapshot") {
		t.Errorf("want failed task types listed, got %q", msg)
	}
	if strings.Contains(msg, "vzdump") {
		t.Errorf("vzdump must be excluded from the message, got %q", msg)
	}
}
