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
				s.ListeningPorts = []models.PortEntry{{Port: 5432, Protocol: "tcp", Process: "postgres", ExePath: "/usr/lib/postgresql/16/bin/postgres"}}
			},
			level: "INFO", msg: "known service",
		},
		{
			// internal-analysis-08-02: a self-reported process name matching a
			// known service, with NO corroborating ExePath (unreadable, or a
			// renamed backdoor listener), must stay WARN, not downgrade to INFO.
			name: "known-service NAME with no corroborating exe path stays WARN",
			mutate: func(s *models.SecurityInfo) {
				s.ListeningPorts = []models.PortEntry{{Port: 5432, Protocol: "tcp", Process: "postgres"}}
			},
			level: "WARN", msg: "unexpected port",
		},
		{
			// internal-analysis-08-02: a name/path substring match alone is
			// spoofable — an unprivileged local attacker fully controls their own
			// binary's name and location (cp mybackdoor ~/postgres && ~/postgres),
			// so /proc/pid/exe resolving under $HOME (not a real system binary
			// directory) must also stay WARN, even though both Process and
			// ExePath contain "postgres".
			name: "known-service NAME with exe path outside system dirs stays WARN",
			mutate: func(s *models.SecurityInfo) {
				s.ListeningPorts = []models.PortEntry{{Port: 5432, Protocol: "tcp", Process: "postgres", ExePath: "/home/attacker/postgres"}}
			},
			level: "WARN", msg: "unexpected port",
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
		{
			name: "apparmor denial groups is WARN",
			mutate: func(s *models.SecurityInfo) {
				s.AppArmorGroups = []models.AppArmorDenial{{Profile: "/usr/sbin/nginx", Operation: "open", Path: "/etc/shadow", Count: 5}}
			},
			level: "WARN", msg: "AppArmor denial group",
		},
		{
			name:   "apparmor denials with no groups is WARN",
			mutate: func(s *models.SecurityInfo) { s.AppArmorDenials = 3 },
			level:  "WARN", msg: "AppArmor denial",
		},
		{
			name: "pam module failures is WARN",
			mutate: func(s *models.SecurityInfo) {
				s.PAMModuleFailures = []models.PAMFailure{{Service: "sudo", User: "bob", Count: 2}}
			},
			level: "WARN", msg: "PAM authentication failure",
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

// TestCheckAppArmorDenials_Clean guards the zero-denial boundary explicitly:
// a zero-value SecurityInfo (no AppArmorGroups, AppArmorDenials == 0) must not
// produce any insight — checkAppArmorDenials should stay silent, not WARN on
// the absence of data.
func TestCheckAppArmorDenials_Clean(t *testing.T) {
	if got := checkAppArmorDenials(models.SecurityInfo{}); len(got) != 0 {
		t.Errorf("no AppArmor denial data should produce no insight, got %+v", got)
	}
}

// TestCheckAppArmorDenials_Unreadable is the regression test for the
// false-OK fix (internal-models-03-01/11-05): a journalctl scan failure
// (AppArmorDenialsUnreadable=true) must disclose an INFO, not silently read
// the same as TestCheckAppArmorDenials_Clean's genuinely-audited-and-clean
// zero-value case.
func TestCheckAppArmorDenials_Unreadable(t *testing.T) {
	got := checkAppArmorDenials(models.SecurityInfo{AppArmorDenialsUnreadable: true})
	if !hasInsightMsg(got, "INFO", "could not be read") {
		t.Errorf("unreadable AppArmor denial log must produce an INFO disclosure, got %+v", got)
	}
}

// TestCheckPAMFailures_Clean is the same boundary guard for PAM module
// failures: no PAMModuleFailures must yield no insight.
func TestCheckPAMFailures_Clean(t *testing.T) {
	if got := checkPAMFailures(models.SecurityInfo{}); len(got) != 0 {
		t.Errorf("no PAM module failures should produce no insight, got %+v", got)
	}
}

// TestCheckSecurityAuditGaps_AIDEDBUnreadable is the regression test for the
// false-OK fix (internal-models-11-05): the AIDE database path existing but
// being unreadable (non-root) must disclose its own INFO, ADDITIVE to
// checkRHELSecurityHardening's "never been initialised" WARN (which still
// fires off the same AIDEDBExists==false / -1 sentinel) — never a silent
// swap of a misleading "aide --init" remediation for the real "run as root"
// fix.
func TestCheckSecurityAuditGaps_AIDEDBUnreadable(t *testing.T) {
	t.Parallel()
	sec := models.SecurityInfo{AIDEInstalled: true, AIDEDBExists: false, AIDEDBUnreadable: true}
	got := checkSecurity(sec)
	if !hasInsightMsg(got, "INFO", "NOT verified") {
		t.Errorf("unreadable AIDE database must produce an INFO disclosure, got %+v", got)
	}
	if !hasInsightMsg(got, "WARN", "never been initialised") {
		t.Errorf("the AIDE-unreadable INFO must be additive to the existing WARN, got %+v", got)
	}
}

// TestCheckSecurityAuditGaps_AIDEDBUnreadable_Clean guards the boundary: a
// genuinely-never-initialised AIDE database (AIDEDBUnreadable left false)
// must NOT produce the unreadable disclosure.
func TestCheckSecurityAuditGaps_AIDEDBUnreadable_Clean(t *testing.T) {
	t.Parallel()
	sec := models.SecurityInfo{AIDEInstalled: true, AIDEDBExists: false}
	if got := checkSecurityAuditGaps(sec); hasInsightMsg(got, "INFO", "NOT verified") {
		t.Errorf("AIDEDBUnreadable=false must not produce the unreadable disclosure, got %+v", got)
	}
}

// TestCheckSecurityAuditGaps_SupportconfigUnreadable is the regression test
// for the false-OK fix (internal-models-11-05): /var/log being unreadable
// (non-root) while searching for supportconfig archives must disclose its
// own INFO, ADDITIVE to checkSUSESecurityHardening's "never run" INFO (which
// still fires off the same SupportconfigLastRunDays==-1 sentinel) — never a
// silent swap of "collect a fresh supportconfig" for the real "run as root"
// fix.
func TestCheckSecurityAuditGaps_SupportconfigUnreadable(t *testing.T) {
	t.Parallel()
	sec := models.SecurityInfo{SupportconfigAvailable: true, SupportconfigLastRunDays: -1, SupportconfigUnreadable: true}
	got := checkSecurity(sec)
	if !hasInsightMsg(got, "INFO", "NOT verified") {
		t.Errorf("unreadable /var/log must produce an INFO disclosure, got %+v", got)
	}
	if !hasInsightMsg(got, "INFO", "never run") {
		t.Errorf("the supportconfig-unreadable INFO must be additive to the existing 'never run' INFO, got %+v", got)
	}
}

// TestCheckSecurityAuditGaps_SupportconfigUnreadable_Clean guards the
// boundary: a genuinely-never-run supportconfig (SupportconfigUnreadable left
// false) must NOT produce the unreadable disclosure.
func TestCheckSecurityAuditGaps_SupportconfigUnreadable_Clean(t *testing.T) {
	t.Parallel()
	sec := models.SecurityInfo{SupportconfigAvailable: true, SupportconfigLastRunDays: -1}
	if got := checkSecurityAuditGaps(sec); hasInsightMsg(got, "INFO", "NOT verified") {
		t.Errorf("SupportconfigUnreadable=false must not produce the unreadable disclosure, got %+v", got)
	}
}
