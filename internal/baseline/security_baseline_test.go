package baseline

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/keyorixhq/dashdiag/internal/models"
)

// testSSHHashes backs the stubbed hashSSHConfigFilesFn so SSH-drift tests don't
// depend on the host's /etc/ssh contents. Default empty = "no SSH config files".
var testSSHHashes map[string]string

func TestMain(m *testing.M) {
	hashSSHConfigFilesFn = func() map[string]string {
		out := make(map[string]string, len(testSSHHashes))
		for k, v := range testSSHHashes {
			out[k] = v
		}
		return out
	}
	os.Exit(m.Run())
}

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

// A new SSH config drop-in (present now, not in the baseline) and a removed one
// (in the baseline, gone now) must both be detected as drift — not just content
// changes to files in both sets. Regression for the gap where dropping
// /etc/ssh/sshd_config.d/99-evil.conf evaded the security drift check.
func TestDiffSecurityBaseline_AddedAndRemovedSSHFiles(t *testing.T) {
	base := &SecurityBaseline{
		SSHConfigHashes: map[string]string{
			"/etc/ssh/sshd_config":               "hash-main",
			"/etc/ssh/sshd_config.d/10-old.conf": "hash-old",
		},
	}
	// Current state: main unchanged, 10-old.conf removed, 99-evil.conf added.
	testSSHHashes = map[string]string{
		"/etc/ssh/sshd_config":                "hash-main",
		"/etc/ssh/sshd_config.d/99-evil.conf": "hash-evil",
	}
	defer func() { testSSHHashes = nil }()

	diff := DiffSecurityBaseline(base, &models.SecurityInfo{})

	if len(diff.AddedSSHFiles) != 1 || diff.AddedSSHFiles[0] != "/etc/ssh/sshd_config.d/99-evil.conf" {
		t.Errorf("AddedSSHFiles = %v, want [99-evil.conf]", diff.AddedSSHFiles)
	}
	if len(diff.RemovedSSHFiles) != 1 || diff.RemovedSSHFiles[0] != "/etc/ssh/sshd_config.d/10-old.conf" {
		t.Errorf("RemovedSSHFiles = %v, want [10-old.conf]", diff.RemovedSSHFiles)
	}
	if len(diff.ChangedSSHFiles) != 0 {
		t.Errorf("ChangedSSHFiles = %v, want none (main unchanged)", diff.ChangedSSHFiles)
	}
	if !diff.HasChanges() {
		t.Error("HasChanges must be true when an SSH config file is added/removed")
	}
}

// A changed SSH file (same path, different hash) is still detected, and a new
// drop-in does not get misreported as a content change.
func TestDiffSecurityBaseline_ChangedSSHFile(t *testing.T) {
	base := &SecurityBaseline{
		SSHConfigHashes: map[string]string{"/etc/ssh/sshd_config": "hash-v1"},
	}
	testSSHHashes = map[string]string{"/etc/ssh/sshd_config": "hash-v2"}
	defer func() { testSSHHashes = nil }()

	diff := DiffSecurityBaseline(base, &models.SecurityInfo{})
	if len(diff.ChangedSSHFiles) != 1 || diff.ChangedSSHFiles[0] != "/etc/ssh/sshd_config" {
		t.Errorf("ChangedSSHFiles = %v, want [sshd_config]", diff.ChangedSSHFiles)
	}
	if len(diff.AddedSSHFiles) != 0 || len(diff.RemovedSSHFiles) != 0 {
		t.Errorf("unexpected add/remove: added=%v removed=%v", diff.AddedSSHFiles, diff.RemovedSSHFiles)
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
