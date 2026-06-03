//go:build linux

package collectors

import (
	"os"
	"path/filepath"
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

func TestParseVzdumpVMID(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name   string
		wantID int
		wantOK bool
	}{
		{"vzdump-qemu-100-2024_06_03-19_16_09.vma.zst", 100, true},
		{"vzdump-lxc-213-2024_06_03-05_42_00.tar.zst", 213, true},
		{"vzdump-qemu-100-2024_06_03-19_16_09.vma.lzo", 100, true},
		{"vzdump-lxc-9-2020_01_01-00_00_00.tar.gz", 9, true},
		{"vzdump-qemu-100.log", 0, false}, // no date/time fields — not an archive form
		{"random-file.txt", 0, false},
		{"vzdump-qemu-notanumber-x.vma.zst", 0, false},
		{"vzdump-foo-100-x.vma.zst", 0, false}, // type must be qemu|lxc
		{"vzdump-qemu", 0, false},              // too few parts
	}
	for _, c := range cases {
		id, ok := parseVzdumpVMID(c.name)
		if id != c.wantID || ok != c.wantOK {
			t.Errorf("parseVzdumpVMID(%q) = (%d,%v), want (%d,%v)", c.name, id, ok, c.wantID, c.wantOK)
		}
	}
}

func TestScanBackupDumpDirs(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	// Two backups for VMID 100 (keep the newer), one for 213, plus noise.
	writeBackupFile(t, dir, "vzdump-qemu-100-2024_06_01-01_00_00.vma.zst", -10*24*time.Hour)
	writeBackupFile(t, dir, "vzdump-qemu-100-2024_06_03-01_00_00.vma.zst", -2*24*time.Hour) // newer
	writeBackupFile(t, dir, "vzdump-lxc-213-2024_06_03-05_42_00.tar.zst", -1*24*time.Hour)
	writeBackupFile(t, dir, "notes.txt", -1*time.Hour) // ignored

	got := scanBackupDumpDirs([]string{dir, "/nonexistent/dump"})
	if len(got) != 2 {
		t.Fatalf("expected 2 VMIDs, got %d: %v", len(got), got)
	}
	// VMID 100 must reflect the *newer* of its two archives (~2 days old).
	age100 := int(time.Since(got[100]).Hours() / 24)
	if age100 != 2 {
		t.Errorf("VMID 100 age = %d days, want 2 (newest archive)", age100)
	}
	if _, ok := got[213]; !ok {
		t.Error("VMID 213 missing from scan")
	}
}

func TestScanBackupDumpDirs_Empty(t *testing.T) {
	t.Parallel()
	if got := scanBackupDumpDirs([]string{t.TempDir()}); len(got) != 0 {
		t.Errorf("empty dir → %d entries, want 0", len(got))
	}
}

// writeBackupFile creates a fake backup archive with a specific mtime offset.
func writeBackupFile(t *testing.T, dir, name string, ageOffset time.Duration) {
	t.Helper()
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, []byte("x"), 0o600); err != nil {
		t.Fatalf("write %s: %v", name, err)
	}
	mt := time.Now().Add(ageOffset)
	if err := os.Chtimes(path, mt, mt); err != nil {
		t.Fatalf("chtimes %s: %v", name, err)
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
