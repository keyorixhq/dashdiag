package analysis

import (
	"testing"

	"github.com/keyorixhq/dashdiag/internal/models"
)

// TestCheckSecurityFull covers the many conditions in checkSecurity beyond the
// core SSH flags (which are pinned in heuristics_security_storage_test.go):
// listening ports, firewall, privilege escalation, SELinux denials, distro
// compliance (crypto-policy/auditd/AIDE/SUSEConnect), and the macOS checks.
// Uses hasInsightMsg to isolate one condition at a time, since checkSecurity
// emits many insights at once. Baseline avoids the always-on SSH defaults.
func TestCheckSecurityFull(t *testing.T) {
	base := func() models.SecurityInfo {
		// StrictModes on + a set idle timeout suppress the default INFO/WARN noise.
		return models.SecurityInfo{SSHStrictModes: true, SSHClientAliveInterval: 300}
	}
	tests := []struct {
		name   string
		mutate func(*models.SecurityInfo)
		level  string
		msg    string
	}{
		{"long login grace time is INFO", func(s *models.SecurityInfo) { s.SSHLoginGraceTime = 120 }, "INFO", "LoginGraceTime"},
		{"x11 forwarding is INFO", func(s *models.SecurityInfo) { s.SSHX11Forwarding = true }, "INFO", "X11Forwarding"},
		{"agent forwarding is INFO", func(s *models.SecurityInfo) { s.SSHAgentForwarding = true }, "INFO", "AgentForwarding"},
		{"no idle timeout is INFO", func(s *models.SecurityInfo) { s.SSHClientAliveInterval = 0; s.SSHAuditSource = "file" }, "INFO", "idle timeout"},
		// False-OK guard: sshd_config present but unreadable (non-root, mode 600) →
		// the SSH directives stay at secure defaults; must surface "NOT audited",
		// not silently read as hardened.
		{"unreadable ssh config is INFO", func(s *models.SecurityInfo) { s.SSHConfigUnreadable = true }, "INFO", "NOT audited"},
		{"many failed logins is CRIT", func(s *models.SecurityInfo) { s.FailedLogins = 25 }, "CRIT", "failed login"},
		{"some failed logins is WARN", func(s *models.SecurityInfo) { s.FailedLogins = 10 }, "WARN", "failed login"},
		{
			name: "unexpected port is WARN",
			mutate: func(s *models.SecurityInfo) {
				s.ListeningPorts = []models.PortEntry{{Port: 1337, Protocol: "tcp", Process: "mystery"}}
			},
			level: "WARN", msg: "unexpected port",
		},
		{
			name: "known-service port is INFO",
			mutate: func(s *models.SecurityInfo) {
				s.ListeningPorts = []models.PortEntry{{Port: 5432, Protocol: "tcp", Process: "postgres"}}
			},
			level: "INFO", msg: "known service",
		},
		{
			name: "cockpit port is INFO",
			mutate: func(s *models.SecurityInfo) {
				s.ListeningPorts = []models.PortEntry{{Port: 9090, Protocol: "tcp", Expected: true}}
			},
			level: "INFO", msg: "Cockpit",
		},
		{
			name: "firewall blocks ssh is CRIT",
			mutate: func(s *models.SecurityInfo) {
				s.FirewallActive = true
				s.SSHAllowed = false
				s.FirewallType = "firewalld"
			},
			level: "CRIT", msg: "not in allowed",
		},
		{"sudo nopasswd is WARN", func(s *models.SecurityInfo) { s.SudoNopasswd = []string{"alice"} }, "WARN", "NOPASSWD"},
		{"unexpected SUID is WARN", func(s *models.SecurityInfo) { s.SUIDBinaries = []string{"/usr/local/bin/x"} }, "WARN", "SUID"},
		{"uid0 user is CRIT", func(s *models.SecurityInfo) { s.UID0Users = []string{"backdoor"} }, "CRIT", "UID 0"},
		{"suspect cron is WARN", func(s *models.SecurityInfo) { s.SuspectCrons = []string{"/etc/cron.d/x"} }, "WARN", "suspect cron"},
		{
			name:   "selinux denials is WARN",
			mutate: func(s *models.SecurityInfo) { s.SELinuxDenials = 15; s.SELinuxMode = "enforcing" },
			level:  "WARN", msg: "SELinux denials",
		},
		{"legacy crypto policy is WARN", func(s *models.SecurityInfo) { s.CryptoPolicy = "LEGACY" }, "WARN", "crypto policy is LEGACY"},
		{
			name:   "auditd no rules is WARN",
			mutate: func(s *models.SecurityInfo) { s.AuditRules = 0; s.SELinuxMode = "enforcing" },
			level:  "WARN", msg: "no active rules",
		},
		{"aide uninitialised is WARN", func(s *models.SecurityInfo) { s.AIDEInstalled = true; s.AIDEDBExists = false }, "WARN", "never been initialised"},
		{
			name:   "aide stale is WARN",
			mutate: func(s *models.SecurityInfo) { s.AIDEInstalled = true; s.AIDEDBExists = true; s.AIDELastRunDays = 10 },
			level:  "WARN", msg: "day(s) old",
		},
		{
			name:   "supportconfig never run is INFO",
			mutate: func(s *models.SecurityInfo) { s.SupportconfigAvailable = true; s.SupportconfigLastRunDays = -1 },
			level:  "INFO", msg: "never run",
		},
		{
			name:   "suseconnect expired is CRIT",
			mutate: func(s *models.SecurityInfo) { s.SUSEConnectRegistered = true; s.SUSEConnectExpiresDays = 0 },
			level:  "CRIT", msg: "EXPIRED",
		},
		{
			name:   "suseconnect expiring within 30d is WARN",
			mutate: func(s *models.SecurityInfo) { s.SUSEConnectRegistered = true; s.SUSEConnectExpiresDays = 20 },
			level:  "WARN", msg: "expires in",
		},
		{
			name:   "macos filevault off is WARN",
			mutate: func(s *models.SecurityInfo) { s.IsDarwin = true; s.SIPEnabled = true; s.GatekeeperEnabled = true },
			level:  "WARN", msg: "FileVault",
		},
		{
			name:   "macos SIP off is CRIT",
			mutate: func(s *models.SecurityInfo) { s.IsDarwin = true; s.FileVaultEnabled = true; s.GatekeeperEnabled = true },
			level:  "CRIT", msg: "SIP",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			sec := base()
			tt.mutate(&sec)
			got := checkSecurity(sec)
			if !hasInsightMsg(got, tt.level, tt.msg) {
				t.Errorf("want %s insight containing %q, got %+v", tt.level, tt.msg, got)
			}
		})
	}
}

// On a host with no sshd at all, SSHClientAliveInterval is its 0 zero-value and
// SSHAuditSource is "" — the "set ClientAliveInterval" INFO must NOT fire, since
// there is no sshd_config to set it in. (TRIAGE §A minor; regression for the
// gate added to the idle-timeout check.)
func TestNoIdleTimeoutSuppressedWhenNoSSHD(t *testing.T) {
	// No SSHAuditSource → nothing was audited.
	noSSHD := models.SecurityInfo{SSHStrictModes: true, SSHClientAliveInterval: 0}
	if hasInsightMsg(checkSecurity(noSSHD), "INFO", "idle timeout") {
		t.Error("idle-timeout INFO should be suppressed when no sshd was audited (SSHAuditSource == \"\")")
	}
	// But once an sshd config IS audited, the missing setting is real → fire.
	withSSHD := models.SecurityInfo{SSHStrictModes: true, SSHClientAliveInterval: 0, SSHAuditSource: "sshd -T"}
	if !hasInsightMsg(checkSecurity(withSSHD), "INFO", "idle timeout") {
		t.Error("idle-timeout INFO should fire when sshd was audited and ClientAliveInterval is unset")
	}
}
