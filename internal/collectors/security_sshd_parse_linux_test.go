//go:build linux

package collectors

import (
	"strings"
	"testing"

	"github.com/keyorixhq/dashdiag/internal/models"
)

// realSSHDOutput is the audited subset of a real `sshd -T` dump (debian:12
// openssh-server) for a known hardened config. Notably AllowUsers comes back as
// ONE LINE PER USER (sshd -T explodes the list), which the parser must accumulate
// — a naive assignment would keep only the last user.
const realSSHDOutput = `port 2222
logingracetime 45
maxauthtries 3
maxsessions 4
clientaliveinterval 300
permitrootlogin no
ignorerhosts yes
hostbasedauthentication no
pubkeyauthentication yes
passwordauthentication no
x11forwarding no
strictmodes yes
permitemptypasswords no
allowtcpforwarding no
allowagentforwarding no
ciphers chacha20-poly1305@openssh.com,aes256-gcm@openssh.com
macs hmac-sha2-256-etm@openssh.com
loglevel VERBOSE
allowusers alice
allowusers bob
allowgroups admins
permituserenvironment no
`

// TestParseSSHFileContentRealSSHD pins the sshd_config parser against real `sshd -T`
// output, so the SSH-hardening verdict fields can't silently drift from the tool's
// actual format (e.g. the one-line-per-user AllowUsers, comma-list Ciphers, VERBOSE
// LogLevel case).
func TestParseSSHFileContentRealSSHD(t *testing.T) {
	var info models.SecurityInfo
	parseSSHFileContent(realSSHDOutput, &info)

	checkBool := func(name string, got, want bool) {
		if got != want {
			t.Errorf("%s = %v, want %v", name, got, want)
		}
	}
	checkInt := func(name string, got, want int) {
		if got != want {
			t.Errorf("%s = %d, want %d", name, got, want)
		}
	}
	checkBool("SSHRootLogin", info.SSHRootLogin, false)
	checkBool("SSHPermitRoot", info.SSHPermitRoot, false)
	checkBool("SSHPasswordAuth", info.SSHPasswordAuth, false)
	checkBool("SSHPubkeyAuth", info.SSHPubkeyAuth, true)
	checkBool("SSHX11Forwarding", info.SSHX11Forwarding, false)
	checkBool("SSHAgentForwarding", info.SSHAgentForwarding, false)
	checkBool("SSHPermitEmptyPwd", info.SSHPermitEmptyPwd, false)
	checkBool("SSHStrictModes", info.SSHStrictModes, true)
	checkBool("SSHIgnoreRhosts", info.SSHIgnoreRhosts, true)
	checkBool("SSHHostbasedAuth", info.SSHHostbasedAuth, false)
	checkBool("SSHPermitUserEnv", info.SSHPermitUserEnv, false)
	checkBool("SSHTCPForwarding", info.SSHTCPForwarding, false)
	checkInt("SSHPort", info.SSHPort, 2222)
	checkInt("SSHLoginGraceTime", info.SSHLoginGraceTime, 45)
	checkInt("SSHMaxAuthTries", info.SSHMaxAuthTries, 3)
	checkInt("SSHMaxSessions", info.SSHMaxSessions, 4)
	checkInt("SSHClientAliveInterval", info.SSHClientAliveInterval, 300)
	if info.SSHLogLevel != "VERBOSE" {
		t.Errorf("SSHLogLevel = %q, want VERBOSE", info.SSHLogLevel)
	}
	if info.SSHCiphers != "chacha20-poly1305@openssh.com,aes256-gcm@openssh.com" {
		t.Errorf("SSHCiphers = %q", info.SSHCiphers)
	}
	if info.SSHMACs != "hmac-sha2-256-etm@openssh.com" {
		t.Errorf("SSHMACs = %q", info.SSHMACs)
	}
	if strings.Join(info.SSHAllowUsers, ",") != "alice,bob" {
		t.Errorf("SSHAllowUsers = %v, want [alice bob] (sshd -T emits one line per user)", info.SSHAllowUsers)
	}
	if strings.Join(info.SSHAllowGroups, ",") != "admins" {
		t.Errorf("SSHAllowGroups = %v, want [admins]", info.SSHAllowGroups)
	}
}

// TestParseSSHFileContentMatchBlock pins the file-parse fallback's Match-block
// handling: a directive inside a conditional Match block is a per-connection
// override, NOT the global policy. A global `PasswordAuthentication no` with a
// `Match`-scoped `yes` must read as hardened (regression: it once produced a false
// "SSH allows password authentication" WARN). `Match all` returns to global scope.
func TestParseSSHFileContentMatchBlock(t *testing.T) {
	cfg := `PasswordAuthentication no
PermitRootLogin no
Match Address 10.0.0.0/8
    PasswordAuthentication yes
    PermitRootLogin yes
Match all
X11Forwarding no
`
	var info models.SecurityInfo
	parseSSHFileContent(cfg, &info)
	if info.SSHPasswordAuth {
		t.Error("SSHPasswordAuth = true, want false (the `yes` is inside a Match block, not global)")
	}
	if info.SSHPermitRoot || info.SSHRootLogin {
		t.Error("root login read as enabled from a Match-scoped override, want global `no`")
	}
	if info.SSHX11Forwarding {
		t.Error("X11Forwarding after `Match all` should be global scope, parsed wrong")
	}
}
