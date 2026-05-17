//go:build linux

package collectors

import (
	"testing"

	"github.com/keyorixhq/dashdiag/internal/models"
)

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
