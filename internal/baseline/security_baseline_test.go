package baseline

import (
	"path/filepath"
	"testing"

	"github.com/keyorixhq/dashdiag/internal/models"
)

func TestBuildSecurityBaseline_PopulatesFields(t *testing.T) {
	info := &models.SecurityInfo{
		SUIDBinaries: []string{"/usr/local/bin/foo", "/usr/local/bin/bar"},
		SudoNopasswd: []string{"deploy ALL=(ALL) NOPASSWD: /usr/bin/systemctl"},
		SuspectCrons: []string{"root: * * * * * /tmp/run.sh"},
	}
	b := BuildSecurityBaseline(info)

	if got := len(b.KnownSUIDs); got != 2 {
		t.Errorf("KnownSUIDs = %d, want 2", got)
	}
	if got := len(b.SudoNopasswd); got != 1 {
		t.Errorf("SudoNopasswd = %d, want 1", got)
	}
	if got := len(b.SuspectCrons); got != 1 {
		t.Errorf("SuspectCrons = %d, want 1", got)
	}
	if b.SavedAt.IsZero() {
		t.Error("SavedAt should be set")
	}
	if b.SSHConfigHashes == nil {
		t.Error("SSHConfigHashes should be non-nil (even if empty)")
	}
}

func TestDiffSecurityBaseline_NewSUIDDetected(t *testing.T) {
	base := &SecurityBaseline{KnownSUIDs: []string{"/usr/bin/sudo"}}
	cur := &models.SecurityInfo{SUIDBinaries: []string{"/usr/bin/sudo", "/usr/local/bin/custom-tool"}}

	diff := DiffSecurityBaseline(base, cur)
	if len(diff.NewSUIDs) != 1 || diff.NewSUIDs[0] != "/usr/local/bin/custom-tool" {
		t.Errorf("NewSUIDs = %v, want [/usr/local/bin/custom-tool]", diff.NewSUIDs)
	}
	if len(diff.RemovedSUIDs) != 0 {
		t.Errorf("RemovedSUIDs = %v, want empty", diff.RemovedSUIDs)
	}
}

func TestDiffSecurityBaseline_RemovedSUIDDetected(t *testing.T) {
	base := &SecurityBaseline{KnownSUIDs: []string{"/usr/bin/sudo", "/usr/bin/gone"}}
	cur := &models.SecurityInfo{SUIDBinaries: []string{"/usr/bin/sudo"}}

	diff := DiffSecurityBaseline(base, cur)
	if len(diff.RemovedSUIDs) != 1 || diff.RemovedSUIDs[0] != "/usr/bin/gone" {
		t.Errorf("RemovedSUIDs = %v, want [/usr/bin/gone]", diff.RemovedSUIDs)
	}
	if len(diff.NewSUIDs) != 0 {
		t.Errorf("NewSUIDs = %v, want empty", diff.NewSUIDs)
	}
}

func TestDiffSecurityBaseline_NewSudoEntryDetected(t *testing.T) {
	base := &SecurityBaseline{SudoNopasswd: []string{"alice ALL=(ALL) NOPASSWD: /usr/bin/foo"}}
	cur := &models.SecurityInfo{SudoNopasswd: []string{
		"alice ALL=(ALL) NOPASSWD: /usr/bin/foo",
		"deploy ALL=(ALL) NOPASSWD: /usr/bin/systemctl restart app",
	}}

	diff := DiffSecurityBaseline(base, cur)
	if len(diff.NewSudoEntries) != 1 {
		t.Fatalf("NewSudoEntries = %v, want 1 entry", diff.NewSudoEntries)
	}
	if diff.NewSudoEntries[0] != "deploy ALL=(ALL) NOPASSWD: /usr/bin/systemctl restart app" {
		t.Errorf("unexpected new sudo entry: %q", diff.NewSudoEntries[0])
	}
}

func TestDiffSecurityBaseline_NoDriftWhenIdentical(t *testing.T) {
	base := &SecurityBaseline{
		KnownSUIDs:   []string{"/usr/bin/sudo"},
		SudoNopasswd: []string{"deploy NOPASSWD: /bin/x"},
		SuspectCrons: []string{"root: * * * * * /tmp/run.sh"},
	}
	cur := &models.SecurityInfo{
		SUIDBinaries: []string{"/usr/bin/sudo"},
		SudoNopasswd: []string{"deploy NOPASSWD: /bin/x"},
		SuspectCrons: []string{"root: * * * * * /tmp/run.sh"},
	}

	diff := DiffSecurityBaseline(base, cur)
	if diff.HasChanges() {
		t.Errorf("expected no changes, got %+v", diff)
	}
}

func TestDiffSecurityBaseline_NoBaselineReturnsFlag(t *testing.T) {
	diff := DiffSecurityBaseline(nil, &models.SecurityInfo{})
	if !diff.NoBaseline {
		t.Error("expected NoBaseline=true when baseline is nil")
	}
	if diff.HasChanges() {
		t.Error("expected HasChanges=false when no baseline")
	}
}

func TestSecurityDiffHasChanges_TrueWhenNewSUIDs(t *testing.T) {
	d := SecurityDiff{NewSUIDs: []string{"/usr/local/bin/x"}}
	if !d.HasChanges() {
		t.Error("HasChanges should be true when NewSUIDs is non-empty")
	}
}

func TestSecurityDiffHasChanges_FalseWhenEmpty(t *testing.T) {
	d := SecurityDiff{}
	if d.HasChanges() {
		t.Error("HasChanges should be false on an empty diff")
	}
	// RemovedSUIDs alone is informational and must not count as drift.
	d2 := SecurityDiff{RemovedSUIDs: []string{"/usr/bin/gone"}}
	if d2.HasChanges() {
		t.Error("HasChanges should be false when only RemovedSUIDs is set")
	}
}

func TestSaveAndLoadSecurityBaseline_RoundTrip(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("HOME", dir)

	// LoadSecurityBaseline returns nil,nil before any save.
	got, err := LoadSecurityBaseline()
	if err != nil {
		t.Fatalf("LoadSecurityBaseline (none): %v", err)
	}
	if got != nil {
		t.Fatalf("expected nil baseline before save, got %+v", got)
	}

	b := &SecurityBaseline{
		Hostname:        "testhost",
		SSHConfigHashes: map[string]string{"/etc/ssh/sshd_config": "abc123"},
		KnownSUIDs:      []string{"/usr/bin/sudo"},
		SudoNopasswd:    []string{"deploy NOPASSWD: /bin/x"},
	}
	if err := SaveSecurityBaseline(b); err != nil {
		t.Fatalf("SaveSecurityBaseline: %v", err)
	}

	// File should be at $HOME/.dsd/security-baseline.json
	want := filepath.Join(dir, ".dsd", "security-baseline.json")
	if SecurityBaselinePath() != want {
		t.Errorf("SecurityBaselinePath = %q, want %q", SecurityBaselinePath(), want)
	}

	loaded, err := LoadSecurityBaseline()
	if err != nil {
		t.Fatalf("LoadSecurityBaseline: %v", err)
	}
	if loaded == nil || loaded.Hostname != "testhost" {
		t.Fatalf("loaded baseline mismatch: %+v", loaded)
	}
	if loaded.SSHConfigHashes["/etc/ssh/sshd_config"] != "abc123" {
		t.Errorf("hash round-trip failed: %v", loaded.SSHConfigHashes)
	}
}
