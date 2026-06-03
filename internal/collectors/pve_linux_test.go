//go:build linux

package collectors

import (
	"testing"
	"time"

	"github.com/keyorixhq/dashdiag/internal/models"
)

func TestParsePVEManagerVersion(t *testing.T) {
	t.Parallel()
	cases := []struct {
		line string
		want string
	}{
		{"pve-manager: 8.2.2 (running version: 8.2.2/abc)", "8.2.2"},
		{"pve-manager/8.2.2/0d5b8f3 (running kernel: 6.8.4-3-pve)", "8.2.2"},
		{"pve-manager: 7.4-3 (running version: 7.4-3/...)", "7.4-3"},
		{"pve-manager", ""},
	}
	for _, c := range cases {
		if got := parsePVEManagerVersion(c.line); got != c.want {
			t.Errorf("parsePVEManagerVersion(%q) = %q, want %q", c.line, got, c.want)
		}
	}
}

func TestBackupAudit(t *testing.T) {
	t.Parallel()
	now := time.Now()
	guests := []models.PVEGuest{
		{VMID: 101, Name: "db-server"},                     // backed up 45 days ago → CRIT
		{VMID: 205, Name: "dev-ct"},                        // backed up 9 days ago → WARN
		{VMID: 108, Name: "backup-ct"},                     // backed up 1 day ago → OK
		{VMID: 110, Name: "neverbacked"},                   // no entry → never (-1)
		{VMID: 999, Name: "template-vm", IsTemplate: true}, // template → skipped
	}
	lastOK := map[int]time.Time{
		101: now.Add(-45 * 24 * time.Hour),
		205: now.Add(-9 * 24 * time.Hour),
		108: now.Add(-1 * 24 * time.Hour),
	}

	got := backupAudit(guests, lastOK)
	if len(got) != 4 {
		t.Fatalf("expected 4 statuses (template skipped), got %d", len(got))
	}

	byVMID := map[int]models.PVEBackupStatus{}
	for _, s := range got {
		byVMID[s.VMID] = s
	}
	if _, ok := byVMID[999]; ok {
		t.Error("template VMID 999 must be skipped")
	}
	if byVMID[101].LastBackupDays != 45 {
		t.Errorf("VMID 101 days = %d, want 45", byVMID[101].LastBackupDays)
	}
	if byVMID[205].LastBackupDays != 9 {
		t.Errorf("VMID 205 days = %d, want 9", byVMID[205].LastBackupDays)
	}
	if byVMID[108].LastBackupDays != 1 {
		t.Errorf("VMID 108 days = %d, want 1", byVMID[108].LastBackupDays)
	}
	if byVMID[110].LastBackupDays != -1 {
		t.Errorf("VMID 110 days = %d, want -1 (never)", byVMID[110].LastBackupDays)
	}
	if byVMID[110].Name != "neverbacked" {
		t.Errorf("VMID 110 name = %q, want neverbacked", byVMID[110].Name)
	}
}

func TestBackupAudit_NoGuests(t *testing.T) {
	t.Parallel()
	if got := backupAudit(nil, map[int]time.Time{}); len(got) != 0 {
		t.Errorf("expected empty audit, got %d entries", len(got))
	}
}

func TestParseSTPState(t *testing.T) {
	t.Parallel()
	cases := []struct {
		in   string
		want bool
	}{
		{"1", true},
		{"1\n", true},
		{" 1 ", true},
		{"0", false},
		{"0\n", false},
		{"", false},
		{"2", false}, // only "1" means enabled
	}
	for _, c := range cases {
		if got := parseSTPState(c.in); got != c.want {
			t.Errorf("parseSTPState(%q) = %v, want %v", c.in, got, c.want)
		}
	}
}
