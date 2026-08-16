//go:build linux

package collectors

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/keyorixhq/dashdiag/internal/models"
)

// parseSSHFile must report whether it actually read the file, and distinguish a
// not-found path (no SSH config there) from a permission-denied one (config
// exists but couldn't be audited → SSHConfigUnreadable, the false-OK guard).
func TestParseSSHFileReadSignal(t *testing.T) {
	// A readable file → true, no unreadable flag, content parsed.
	dir := t.TempDir()
	p := filepath.Join(dir, "sshd_config")
	if err := os.WriteFile(p, []byte("PermitRootLogin yes\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	var info models.SecurityInfo
	if !parseSSHFile(p, &info) {
		t.Fatal("readable file: parseSSHFile returned false")
	}
	if info.SSHConfigUnreadable {
		t.Error("readable file wrongly flagged unreadable")
	}
	if !info.SSHPermitRoot {
		t.Error("content not parsed (PermitRootLogin yes)")
	}

	// A not-found path → false, but NOT flagged unreadable (no SSH config here is
	// not the same as a config we couldn't read).
	var info2 models.SecurityInfo
	if parseSSHFile(filepath.Join(dir, "does-not-exist"), &info2) {
		t.Error("missing file: parseSSHFile returned true")
	}
	if info2.SSHConfigUnreadable {
		t.Error("missing file wrongly flagged unreadable (would false-fire on hosts without sshd)")
	}
}

// TestParseSSHFile_CapsOversizedRealFile guards read-bounding-10 end-to-end
// via a REAL file on disk (the fixture-Replay side of the shared fsaccess.go
// cap is already covered in fsaccess_cap_test.go): an sshd_config far larger
// than maxCappedFileBytes must still be read and parsed without unbounded
// growth in parseSSHFile's own accumulation loop. openFile's underlying cap
// is tail-preserving, so a directive placed at the very end of the file must
// still be picked up.
func TestParseSSHFile_CapsOversizedRealFile(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "sshd_config")
	const paddingLine = "# padding line to bulk up the file\n"
	repeats := (maxCappedFileBytes*2)/len(paddingLine) + 1
	content := strings.Repeat(paddingLine, repeats) + "Port 2222\n"
	if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	var info models.SecurityInfo
	if !parseSSHFile(p, &info) {
		t.Fatal("parseSSHFile returned false for a large-but-readable file")
	}
	if info.SSHPort != 2222 {
		t.Errorf("SSHPort = %d, want 2222 (the tail-preserved directive)", info.SSHPort)
	}
}

// ── SSH config parser tests ──────────────────────────────────────────────────

// Minimal hardened sshd_config (passes all checks)
const sshdConfigHardened = `
Port 2222
Protocol 2
PermitRootLogin no
PasswordAuthentication no
PubkeyAuthentication yes
PermitEmptyPasswords no
StrictModes yes
MaxAuthTries 4
LoginGraceTime 60
X11Forwarding no
AllowAgentForwarding no
ClientAliveInterval 300
ClientAliveCountMax 3
AllowUsers deploy ansible
AllowGroups sshusers
`

// Deliberately misconfigured sshd_config
const sshdConfigWeak = `
PermitRootLogin yes
PasswordAuthentication yes
PermitEmptyPasswords yes
StrictModes no
MaxAuthTries 10
LoginGraceTime 120
X11Forwarding yes
AllowAgentForwarding yes
`

// Realistic cloud default (mostly fine, missing idle timeout)
const sshdConfigCloudDefault = `
PermitRootLogin prohibit-password
PasswordAuthentication no
PubkeyAuthentication yes
X11Forwarding yes
PrintMotd no
AcceptEnv LANG LC_*
Subsystem sftp /usr/lib/openssh/sftp-server
`

func applySSHContent(content string) models.SecurityInfo {
	info := models.SecurityInfo{
		SSHPubkeyAuth:  true,
		SSHStrictModes: true,
	}
	parseSSHFileContent(content, &info)
	return info
}

func TestParseSSHFileHardened(t *testing.T) {
	info := applySSHContent(sshdConfigHardened)

	if info.SSHPermitRoot {
		t.Error("SSHPermitRoot should be false (PermitRootLogin no)")
	}
	if info.SSHPasswordAuth {
		t.Error("SSHPasswordAuth should be false")
	}
	if info.SSHPermitEmptyPwd {
		t.Error("SSHPermitEmptyPwd should be false")
	}
	if !info.SSHStrictModes {
		t.Error("SSHStrictModes should be true")
	}
	if info.SSHMaxAuthTries != 4 {
		t.Errorf("SSHMaxAuthTries = %d, want 4", info.SSHMaxAuthTries)
	}
	if info.SSHLoginGraceTime != 60 {
		t.Errorf("SSHLoginGraceTime = %d, want 60", info.SSHLoginGraceTime)
	}
	if info.SSHX11Forwarding {
		t.Error("SSHX11Forwarding should be false")
	}
	if info.SSHAgentForwarding {
		t.Error("SSHAgentForwarding should be false")
	}
	if info.SSHClientAliveInterval != 300 {
		t.Errorf("SSHClientAliveInterval = %d, want 300", info.SSHClientAliveInterval)
	}
	if info.SSHPort != 2222 {
		t.Errorf("SSHPort = %d, want 2222", info.SSHPort)
	}
	if len(info.SSHAllowUsers) != 2 {
		t.Errorf("SSHAllowUsers len = %d, want 2", len(info.SSHAllowUsers))
	}
	if len(info.SSHAllowGroups) != 1 {
		t.Errorf("SSHAllowGroups len = %d, want 1", len(info.SSHAllowGroups))
	}
}

func TestParseSSHFileWeak(t *testing.T) {
	info := applySSHContent(sshdConfigWeak)

	if !info.SSHPermitRoot {
		t.Error("SSHPermitRoot should be true (PermitRootLogin yes)")
	}
	if !info.SSHPasswordAuth {
		t.Error("SSHPasswordAuth should be true")
	}
	if !info.SSHPermitEmptyPwd {
		t.Error("SSHPermitEmptyPwd should be true")
	}
	if info.SSHStrictModes {
		t.Error("SSHStrictModes should be false (StrictModes no)")
	}
	if info.SSHMaxAuthTries != 10 {
		t.Errorf("SSHMaxAuthTries = %d, want 10", info.SSHMaxAuthTries)
	}
	if info.SSHLoginGraceTime != 120 {
		t.Errorf("SSHLoginGraceTime = %d, want 120", info.SSHLoginGraceTime)
	}
	if !info.SSHX11Forwarding {
		t.Error("SSHX11Forwarding should be true")
	}
	if !info.SSHAgentForwarding {
		t.Error("SSHAgentForwarding should be true")
	}
}

func TestParseSSHFileCloudDefault(t *testing.T) {
	info := applySSHContent(sshdConfigCloudDefault)

	// prohibit-password = root can use key but not password — SSHPermitRoot should be false
	if info.SSHPermitRoot {
		t.Error("SSHPermitRoot should be false for 'prohibit-password'")
	}
	if info.SSHPasswordAuth {
		t.Error("SSHPasswordAuth should be false")
	}
	// X11Forwarding yes is common in cloud defaults
	if !info.SSHX11Forwarding {
		t.Error("SSHX11Forwarding should be true")
	}
	// No ClientAliveInterval set — should stay 0
	if info.SSHClientAliveInterval != 0 {
		t.Errorf("SSHClientAliveInterval = %d, want 0 (not configured)", info.SSHClientAliveInterval)
	}
}

func TestParseSSHDuration(t *testing.T) {
	cases := []struct {
		in   string
		want int
	}{
		{"60", 60},
		{"60s", 60},
		{"1m", 60},
		{"1m30s", 90},
		{"2m", 120},
		{"0", 0},
		{"none", 0},
		{"1h", 3600},
	}
	for _, c := range cases {
		got := parseSSHDuration(c.in)
		if got != c.want {
			t.Errorf("parseSSHDuration(%q) = %d, want %d", c.in, got, c.want)
		}
	}
}

func TestSSHIgnoresComments(t *testing.T) {
	t.Parallel()
	config := `
# This is a comment
PermitRootLogin yes
# PasswordAuthentication no — commented out should not apply
`
	info := applySSHContent(config)
	if !info.SSHPermitRoot {
		t.Error("PermitRootLogin yes should parse even with comments around it")
	}
	if info.SSHPasswordAuth {
		t.Error("commented-out PasswordAuthentication no should not disable password auth")
	}
}

// TestSSHDangerousDefaultsNotClearedByComments guards the false-OK class fixed in
// the 2026-07-19 guard sweep. parseSSHConfig pre-initialises PasswordAuthentication,
// AllowTcpForwarding, and AllowAgentForwarding to true (their OpenSSH compiled
// defaults) before calling parseSSHFileContent. A config where those lines are
// commented out must leave the pre-set true value intact — a comment is not an
// explicit "no".
func TestSSHDangerousDefaultsNotClearedByComments(t *testing.T) {
	t.Parallel()
	config := `# PasswordAuthentication yes
# AllowTcpForwarding yes
# AllowAgentForwarding yes
`
	info := models.SecurityInfo{
		SSHPasswordAuth:    true,
		SSHTCPForwarding:   true,
		SSHAgentForwarding: true,
	}
	parseSSHFileContent(config, &info)
	if !info.SSHPasswordAuth {
		t.Error("commented PasswordAuthentication must not clear the pre-set dangerous default")
	}
	if !info.SSHTCPForwarding {
		t.Error("commented AllowTcpForwarding must not clear the pre-set dangerous default")
	}
	if !info.SSHAgentForwarding {
		t.Error("commented AllowAgentForwarding must not clear the pre-set dangerous default")
	}
}
