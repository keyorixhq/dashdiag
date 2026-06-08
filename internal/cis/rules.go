package cis

import (
	"fmt"
	"os"
	"strings"

	"github.com/keyorixhq/dashdiag/internal/models"
)

// CISRules is the full benchmark rule set: CIS Ubuntu 22.04 LTS L1+L2
// covering SSH (5.2.x), network (3.x), audit (4.x), auth (5.x), files (6.x).
var CISRules []Rule

func init() {
	CISRules = buildRules()
}

//nolint:cyclop,funlen // rule registry — each entry is a self-contained check, splitting would harm readability
func buildRules() []Rule {
	return []Rule{

		// ── 5.2 SSH Server Configuration ─────────────────────────────────────

		{ID: "5.2.1", StigID: "V-238201", Framework: "BOTH", Level: 1, Section: "SSH",
			Description:     "Ensure permissions on /etc/ssh/sshd_config are configured (0600)",
			StigDescription: "The SSH daemon configuration file must have mode 0600 or less permissive",
			Check: func(sec models.SecurityInfo, _ models.KernelSecurityInfo) models.CISResult {
				r := ruleByID("5.2.1")
				fi, err := os.Stat("/etc/ssh/sshd_config")
				if err != nil {
					return skipr(r, "sshd_config not found")
				}
				if fi.Mode().Perm()&^0o600 != 0 {
					return failr(r, fmt.Sprintf("sshd_config mode %o", fi.Mode().Perm()),
						"chmod 600 /etc/ssh/sshd_config")
				}
				return pass(r)
			}},

		{ID: "5.2.2", StigID: "V-238202", Framework: "BOTH", Level: 1, Section: "SSH",
			Description: "Ensure SSH access is limited (AllowUsers or AllowGroups set)",
			Check: func(sec models.SecurityInfo, _ models.KernelSecurityInfo) models.CISResult {
				r := ruleByID("5.2.2")
				if len(sec.SSHAllowUsers) == 0 && len(sec.SSHAllowGroups) == 0 {
					return failr(r, "AllowUsers and AllowGroups not configured",
						"set AllowUsers or AllowGroups in /etc/ssh/sshd_config")
				}
				return pass(r)
			}},

		{ID: "5.2.5", StigID: "V-238209",
			StigDescription: "The SSH daemon must use an approved log level", Framework: "BOTH", Level: 1, Section: "SSH",
			Description: "Ensure SSH LogLevel is INFO or VERBOSE",
			Check: func(sec models.SecurityInfo, _ models.KernelSecurityInfo) models.CISResult {
				r := ruleByID("5.2.5")
				level := sec.SSHLogLevel
				if level == "" {
					level = "INFO" // OpenSSH default
				}
				if level != "INFO" && level != "VERBOSE" {
					return failr(r, fmt.Sprintf("LogLevel is %q", level),
						"set LogLevel INFO in /etc/ssh/sshd_config")
				}
				return pass(r)
			}},

		{ID: "5.2.6", StigID: "V-238216",
			StigDescription: "The SSH daemon must not allow X11 forwarding", Framework: "BOTH", Level: 1, Section: "SSH",
			Description: "Ensure SSH X11 forwarding is disabled",
			Check: func(sec models.SecurityInfo, _ models.KernelSecurityInfo) models.CISResult {
				r := ruleByID("5.2.6")
				if sec.SSHX11Forwarding {
					return failr(r, "X11Forwarding yes", "set X11Forwarding no in /etc/ssh/sshd_config")
				}
				return pass(r)
			}},

		{ID: "5.2.7", StigID: "V-238217",
			StigDescription: "The SSH daemon must limit authentication attempts", Framework: "BOTH", Level: 1, Section: "SSH",
			Description: "Ensure SSH MaxAuthTries is 4 or less",
			Check: func(sec models.SecurityInfo, _ models.KernelSecurityInfo) models.CISResult {
				r := ruleByID("5.2.7")
				v := sec.SSHMaxAuthTries
				if v == 0 {
					v = 6 // OpenSSH default
				}
				if v > 4 {
					return failr(r, fmt.Sprintf("MaxAuthTries is %d", v),
						"set MaxAuthTries 4 in /etc/ssh/sshd_config")
				}
				return pass(r)
			}},

		{ID: "5.2.8", StigID: "V-238218",
			StigDescription: "The SSH daemon must ignore .rhosts files", Framework: "BOTH", Level: 1, Section: "SSH",
			Description: "Ensure SSH IgnoreRhosts is enabled",
			Check: func(sec models.SecurityInfo, _ models.KernelSecurityInfo) models.CISResult {
				r := ruleByID("5.2.8")
				if !sec.SSHIgnoreRhosts {
					return failr(r, "IgnoreRhosts is disabled",
						"set IgnoreRhosts yes in /etc/ssh/sshd_config")
				}
				return pass(r)
			}},

		{ID: "5.2.9", StigID: "V-238219",
			StigDescription: "The SSH daemon must not allow host-based authentication", Framework: "BOTH", Level: 1, Section: "SSH",
			Description: "Ensure SSH HostbasedAuthentication is disabled",
			Check: func(sec models.SecurityInfo, _ models.KernelSecurityInfo) models.CISResult {
				r := ruleByID("5.2.9")
				if sec.SSHHostbasedAuth {
					return failr(r, "HostbasedAuthentication is enabled",
						"set HostbasedAuthentication no in /etc/ssh/sshd_config")
				}
				return pass(r)
			}},

		{ID: "5.2.10", StigID: "V-238210",
			StigDescription: "The SSH daemon must not allow root logins", Framework: "BOTH", Level: 1, Section: "SSH",
			Description: "Ensure SSH root login is disabled",
			Check: func(sec models.SecurityInfo, _ models.KernelSecurityInfo) models.CISResult {
				r := ruleByID("5.2.10")
				if sec.SSHPermitRoot {
					return failr(r, "PermitRootLogin is not 'no' or 'prohibit-password'",
						"set PermitRootLogin no in /etc/ssh/sshd_config")
				}
				return pass(r)
			}},

		{ID: "5.2.11", StigID: "V-238211",
			StigDescription: "The SSH daemon must not allow empty passwords", Framework: "BOTH", Level: 1, Section: "SSH",
			Description: "Ensure SSH PermitEmptyPasswords is disabled",
			Check: func(sec models.SecurityInfo, _ models.KernelSecurityInfo) models.CISResult {
				r := ruleByID("5.2.11")
				if sec.SSHPermitEmptyPwd {
					return failr(r, "PermitEmptyPasswords yes",
						"set PermitEmptyPasswords no in /etc/ssh/sshd_config")
				}
				return pass(r)
			}},

		{ID: "5.2.12", StigID: "V-238212",
			StigDescription: "The SSH daemon must not permit user environment variables", Framework: "BOTH", Level: 1, Section: "SSH",
			Description: "Ensure SSH PermitUserEnvironment is disabled",
			Check: func(sec models.SecurityInfo, _ models.KernelSecurityInfo) models.CISResult {
				r := ruleByID("5.2.12")
				if sec.SSHPermitUserEnv {
					return failr(r, "PermitUserEnvironment yes — users can override PATH/LD_PRELOAD",
						"set PermitUserEnvironment no in /etc/ssh/sshd_config")
				}
				return pass(r)
			}},

		{ID: "5.2.13", StigID: "V-238220",
			StigDescription: "The SSH daemon must set a timeout interval on idle sessions", Framework: "BOTH", Level: 1, Section: "SSH",
			Description: "Ensure SSH idle timeout is configured (ClientAliveInterval > 0)",
			Check: func(sec models.SecurityInfo, _ models.KernelSecurityInfo) models.CISResult {
				r := ruleByID("5.2.13")
				if sec.SSHClientAliveInterval == 0 {
					return failr(r, "ClientAliveInterval not set — sessions never time out",
						"set ClientAliveInterval 300 and ClientAliveCountMax 3 in /etc/ssh/sshd_config")
				}
				return pass(r)
			}},

		{ID: "5.2.14", StigID: "V-238206", Framework: "BOTH", Level: 1, Section: "SSH",
			Description:     "Ensure SSH LoginGraceTime is 60 seconds or less",
			StigDescription: "The SSH daemon must set the login grace time to 60 seconds or less",
			Check: func(sec models.SecurityInfo, _ models.KernelSecurityInfo) models.CISResult {
				r := ruleByID("5.2.14")
				v := sec.SSHLoginGraceTime
				if v == 0 {
					v = 120 // OpenSSH default
				}
				if v > 60 {
					return failr(r, fmt.Sprintf("LoginGraceTime is %ds", v),
						"set LoginGraceTime 60 in /etc/ssh/sshd_config")
				}
				return pass(r)
			}},

		{ID: "5.2.15", StigID: "V-238225",
			StigDescription: "The SSH daemon must display a login banner", Framework: "BOTH", Level: 1, Section: "SSH",
			Description: "Ensure SSH warning banner is configured",
			Check: func(sec models.SecurityInfo, _ models.KernelSecurityInfo) models.CISResult {
				r := ruleByID("5.2.15")
				if sec.SSHBanner == "" || strings.EqualFold(sec.SSHBanner, "none") {
					return failr(r, "Banner not configured",
						"set Banner /etc/issue.net in /etc/ssh/sshd_config")
				}
				return pass(r)
			}},

		{ID: "5.2.17", StigID: "V-238222",
			StigDescription: "The SSH daemon must not allow TCP port forwarding", Framework: "BOTH", Level: 1, Section: "SSH",
			Description: "Ensure SSH AllowTcpForwarding is disabled",
			Check: func(sec models.SecurityInfo, _ models.KernelSecurityInfo) models.CISResult {
				r := ruleByID("5.2.17")
				if sec.SSHTCPForwarding {
					return failr(r, "AllowTcpForwarding yes — can be used to pivot through this host",
						"set AllowTcpForwarding no in /etc/ssh/sshd_config")
				}
				return pass(r)
			}},

		{ID: "5.2.18", StigID: "V-238223", Framework: "BOTH", Level: 1, Section: "SSH",
			Description: "Ensure SSH MaxStartups is configured",
			Check: func(sec models.SecurityInfo, _ models.KernelSecurityInfo) models.CISResult {
				r := ruleByID("5.2.18")
				if sec.SSHMaxStartups == "" {
					return failr(r, "MaxStartups not set (default allows 100 unauthenticated connections)",
						"set MaxStartups 10:30:60 in /etc/ssh/sshd_config")
				}
				return pass(r)
			}},

		{ID: "5.2.19", StigID: "V-238224", Framework: "BOTH", Level: 1, Section: "SSH",
			Description: "Ensure SSH MaxSessions is 10 or less",
			Check: func(sec models.SecurityInfo, _ models.KernelSecurityInfo) models.CISResult {
				r := ruleByID("5.2.19")
				v := sec.SSHMaxSessions
				if v == 0 {
					v = 10 // OpenSSH default
				}
				if v > 10 {
					return failr(r, fmt.Sprintf("MaxSessions is %d", v),
						"set MaxSessions 10 in /etc/ssh/sshd_config")
				}
				return pass(r)
			}},

		// ── 3.x Network ───────────────────────────────────────────────────────

		{ID: "3.1.1", StigID: "V-238327",
			StigDescription: "IP forwarding must be disabled", Framework: "BOTH", Level: 1, Section: "Network",
			Description: "Ensure IP forwarding is disabled",
			Check: func(_ models.SecurityInfo, _ models.KernelSecurityInfo) models.CISResult {
				r := ruleByID("3.1.1")
				return checkSysctl(r, "/proc/sys/net/ipv4/ip_forward", "0",
					"net.ipv4.ip_forward=0 is not set — IP forwarding is on",
					"sysctl -w net.ipv4.ip_forward=0 && add to /etc/sysctl.d/99-cis.conf")
			}},

		{ID: "3.2.1", StigID: "V-238328",
			StigDescription: "Source routing must be disabled", Framework: "BOTH", Level: 1, Section: "Network",
			Description: "Ensure source routed packets are not accepted",
			Check: func(_ models.SecurityInfo, _ models.KernelSecurityInfo) models.CISResult {
				r := ruleByID("3.2.1")
				return checkSysctl(r, "/proc/sys/net/ipv4/conf/all/accept_source_route", "0",
					"accept_source_route is 1 — source routed packets accepted",
					"sysctl -w net.ipv4.conf.all.accept_source_route=0")
			}},

		{ID: "3.2.2", StigID: "V-238329",
			StigDescription: "ICMP redirects must not be accepted", Framework: "BOTH", Level: 1, Section: "Network",
			Description: "Ensure ICMP redirects are not accepted",
			Check: func(_ models.SecurityInfo, _ models.KernelSecurityInfo) models.CISResult {
				r := ruleByID("3.2.2")
				return checkSysctl(r, "/proc/sys/net/ipv4/conf/all/accept_redirects", "0",
					"accept_redirects is 1 — ICMP redirects accepted",
					"sysctl -w net.ipv4.conf.all.accept_redirects=0")
			}},

		{ID: "3.2.4", StigID: "V-238331",
			StigDescription: "Suspicious packets must be logged", Framework: "BOTH", Level: 1, Section: "Network",
			Description: "Ensure suspicious packets are logged (log_martians)",
			Check: func(_ models.SecurityInfo, _ models.KernelSecurityInfo) models.CISResult {
				r := ruleByID("3.2.4")
				return checkSysctl(r, "/proc/sys/net/ipv4/conf/all/log_martians", "1",
					"log_martians is 0 — martian packets not logged",
					"sysctl -w net.ipv4.conf.all.log_martians=1")
			}},

		// ── 4.x Logging and Auditing ──────────────────────────────────────────

		{ID: "4.1.1", StigID: "V-238360",
			StigDescription: "The Ubuntu operating system must have the auditd package installed", Framework: "BOTH", Level: 1, Section: "Audit",
			Description: "Ensure auditd is installed and running",
			Check: func(sec models.SecurityInfo, _ models.KernelSecurityInfo) models.CISResult {
				r := ruleByID("4.1.1")
				if sec.AuditRules == -1 {
					return failr(r, "auditd not installed or not running",
						"apt install auditd && systemctl enable --now auditd")
				}
				return pass(r)
			}},

		{ID: "4.1.2", StigID: "V-238361",
			StigDescription: "The auditd service must be running and enabled", Framework: "BOTH", Level: 1, Section: "Audit",
			Description: "Ensure auditd has rules configured",
			Check: func(sec models.SecurityInfo, _ models.KernelSecurityInfo) models.CISResult {
				r := ruleByID("4.1.2")
				if sec.AuditRules == -1 {
					return skipr(r, "auditd not available")
				}
				if sec.AuditRules == 0 {
					return failr(r, "auditd running but no rules loaded",
						"install rules: cp /usr/share/doc/auditd/examples/stig.rules /etc/audit/rules.d/ && augenrules --load")
				}
				return pass(r)
			}},

		// ── 5.3/5.4 Auth ──────────────────────────────────────────────────────

		{ID: "5.4.1", StigID: "V-238380", Framework: "BOTH", Level: 1, Section: "Auth",
			Description: "Ensure password expiration is 365 days or less",
			Check: func(_ models.SecurityInfo, _ models.KernelSecurityInfo) models.CISResult {
				r := ruleByID("5.4.1")
				data, err := os.ReadFile("/etc/login.defs") // #nosec G304
				if err != nil {
					return skipr(r, "could not read /etc/login.defs")
				}
				for _, line := range strings.Split(string(data), "\n") {
					if strings.HasPrefix(strings.TrimSpace(line), "#") {
						continue
					}
					if strings.HasPrefix(line, "PASS_MAX_DAYS") {
						fields := strings.Fields(line)
						if len(fields) >= 2 {
							days := 0
							fmt.Sscanf(fields[1], "%d", &days) //nolint:errcheck
							if days > 365 || days == 0 {
								return failr(r, fmt.Sprintf("PASS_MAX_DAYS is %d", days),
									"set PASS_MAX_DAYS 365 in /etc/login.defs")
							}
						}
						return pass(r)
					}
				}
				return failr(r, "PASS_MAX_DAYS not set in /etc/login.defs",
					"add PASS_MAX_DAYS 365 to /etc/login.defs")
			}},

		// ── 6.x System Maintenance ────────────────────────────────────────────

		{ID: "6.1.1", StigID: "V-238401", Framework: "BOTH", Level: 1, Section: "Files",
			Description: "Ensure /etc/passwd permissions are 644 or stricter",
			Check: func(_ models.SecurityInfo, _ models.KernelSecurityInfo) models.CISResult {
				r := ruleByID("6.1.1")
				return checkFilePerm(r, "/etc/passwd", 0o644, "chmod 644 /etc/passwd")
			}},

		{ID: "6.1.2", StigID: "V-238402", Framework: "BOTH", Level: 1, Section: "Files",
			Description: "Ensure /etc/shadow permissions are 000 or 640",
			Check: func(_ models.SecurityInfo, _ models.KernelSecurityInfo) models.CISResult {
				r := ruleByID("6.1.2")
				return checkFilePerm(r, "/etc/shadow", 0o640, "chmod 000 /etc/shadow")
			}},

		{ID: "6.1.3", StigID: "V-238403", Framework: "BOTH", Level: 1, Section: "Files",
			Description: "Ensure /etc/group permissions are 644 or stricter",
			Check: func(_ models.SecurityInfo, _ models.KernelSecurityInfo) models.CISResult {
				r := ruleByID("6.1.3")
				return checkFilePerm(r, "/etc/group", 0o644, "chmod 644 /etc/group")
			}},

		{ID: "6.2.2", StigID: "V-238410", Framework: "BOTH", Level: 1, Section: "Users",
			Description: "Ensure no legacy '+' entries in /etc/passwd, /etc/shadow, /etc/group",
			Check: func(_ models.SecurityInfo, _ models.KernelSecurityInfo) models.CISResult {
				r := ruleByID("6.2.2")
				for _, path := range []string{"/etc/passwd", "/etc/shadow", "/etc/group"} {
					data, err := os.ReadFile(path) // #nosec G304
					if err != nil {
						continue
					}
					for _, line := range strings.Split(string(data), "\n") {
						if strings.HasPrefix(strings.TrimSpace(line), "+") {
							return failr(r, fmt.Sprintf("legacy NIS '+' entry in %s", path),
								fmt.Sprintf("remove the '+' line from %s", path))
						}
					}
				}
				return pass(r)
			}},

		{ID: "6.2.3", StigID: "V-238411", Framework: "BOTH", Level: 1, Section: "Users",
			Description: "Ensure root is the only UID 0 account",
			Check: func(sec models.SecurityInfo, _ models.KernelSecurityInfo) models.CISResult {
				r := ruleByID("6.2.3")
				if len(sec.UID0Users) > 0 {
					return failr(r, fmt.Sprintf("UID 0 accounts: %s", strings.Join(sec.UID0Users, ", ")),
						"lock or remove these accounts: passwd -l <user>")
				}
				return pass(r)
			}},

		// ── STIG-only rules (no direct CIS equivalent) ────────────────────────

		// V-238213: Approved ciphers — STIG mandates only FIPS-approved ciphers
		{ID: "V-238213", Framework: "STIG", Level: 1, Section: "SSH",
			Description: "The SSH daemon must use FIPS-approved ciphers",
			Check: func(sec models.SecurityInfo, _ models.KernelSecurityInfo) models.CISResult {
				r := ruleByID("V-238213")
				if sec.SSHCiphers == "" {
					return failr(r, "Ciphers not explicitly configured — defaults may include weak ciphers",
						"set Ciphers aes128-ctr,aes192-ctr,aes256-ctr,aes128-gcm@openssh.com,aes256-gcm@openssh.com in /etc/ssh/sshd_config")
				}
				weak := []string{"arcfour", "blowfish", "cast128", "3des", "des"}
				for _, w := range weak {
					if strings.Contains(strings.ToLower(sec.SSHCiphers), w) {
						return failr(r, fmt.Sprintf("weak cipher in Ciphers: %q", w),
							"remove weak ciphers — use only aes*-ctr and aes*-gcm@openssh.com variants")
					}
				}
				return pass(r)
			}},

		// V-238214: Approved MACs — STIG mandates only FIPS-approved MACs
		{ID: "V-238214", Framework: "STIG", Level: 1, Section: "SSH",
			Description: "The SSH daemon must use FIPS-approved message authentication codes",
			Check: func(sec models.SecurityInfo, _ models.KernelSecurityInfo) models.CISResult {
				r := ruleByID("V-238214")
				if sec.SSHMACs == "" {
					return failr(r, "MACs not explicitly configured — defaults may include weak MACs",
						"set MACs hmac-sha2-256,hmac-sha2-512,hmac-sha2-256-etm@openssh.com,hmac-sha2-512-etm@openssh.com in /etc/ssh/sshd_config")
				}
				weak := []string{"md5", "sha1", "umac-64", "ripemd"}
				for _, w := range weak {
					if strings.Contains(strings.ToLower(sec.SSHMACs), w) {
						return failr(r, fmt.Sprintf("weak MAC in MACs: %q", w),
							"remove weak MACs — use only hmac-sha2-256 and hmac-sha2-512 variants")
					}
				}
				return pass(r)
			}},

		// V-238215: Approved key exchange algorithms
		{ID: "V-238215", Framework: "STIG", Level: 1, Section: "SSH",
			Description: "The SSH daemon must use approved key exchange algorithms",
			Check: func(sec models.SecurityInfo, _ models.KernelSecurityInfo) models.CISResult {
				r := ruleByID("V-238215")
				if sec.SSHKexAlgorithms == "" {
					return failr(r, "KexAlgorithms not explicitly configured",
						"set KexAlgorithms ecdh-sha2-nistp256,ecdh-sha2-nistp384,ecdh-sha2-nistp521,diffie-hellman-group-exchange-sha256 in /etc/ssh/sshd_config")
				}
				weak := []string{"diffie-hellman-group1", "diffie-hellman-group14-sha1", "gss-gex-sha1"}
				for _, w := range weak {
					if strings.Contains(strings.ToLower(sec.SSHKexAlgorithms), w) {
						return failr(r, fmt.Sprintf("weak key exchange algorithm: %q", w),
							"remove weak KexAlgorithms — avoid SHA-1 and Group 1/14")
					}
				}
				return pass(r)
			}},

		// V-238221: ClientAliveCountMax must be 0 — STIG is stricter than CIS
		{ID: "V-238221", Framework: "STIG", Level: 1, Section: "SSH",
			Description: "The SSH daemon must set ClientAliveCountMax to 0",
			Check: func(sec models.SecurityInfo, _ models.KernelSecurityInfo) models.CISResult {
				r := ruleByID("V-238221")
				// We don't currently parse ClientAliveCountMax — treat as manual
				return models.CISResult{
					ID: r.ID, Framework: "STIG", Level: r.Level, Section: r.Section,
					Description: r.Description, Status: models.CISManual,
					Finding: "run: grep -i ClientAliveCountMax /etc/ssh/sshd_config — value must be 0",
				}
			}},

		// V-238226: SSH StrictModes
		{ID: "V-238226", Framework: "STIG", Level: 1, Section: "SSH",
			Description: "The SSH daemon must perform strict mode checking on user home directories",
			Check: func(sec models.SecurityInfo, _ models.KernelSecurityInfo) models.CISResult {
				r := ruleByID("V-238226")
				if !sec.SSHStrictModes {
					return failr(r, "StrictModes is disabled",
						"set StrictModes yes in /etc/ssh/sshd_config")
				}
				return pass(r)
			}},

		// V-238380 STIG version: PASS_MAX_DAYS must be 60 (stricter than CIS 365)
		{ID: "V-238380", Framework: "STIG", Level: 1, Section: "Auth",
			Description: "The Ubuntu OS must enforce a 60-day maximum password age",
			Check: func(_ models.SecurityInfo, _ models.KernelSecurityInfo) models.CISResult {
				r := ruleByID("V-238380")
				data, err := os.ReadFile("/etc/login.defs") // #nosec G304
				if err != nil {
					return skipr(r, "could not read /etc/login.defs")
				}
				for _, line := range strings.Split(string(data), "\n") {
					if strings.HasPrefix(strings.TrimSpace(line), "#") {
						continue
					}
					if strings.HasPrefix(line, "PASS_MAX_DAYS") {
						fields := strings.Fields(line)
						if len(fields) >= 2 {
							days := 0
							fmt.Sscanf(fields[1], "%d", &days) //nolint:errcheck
							if days > 60 || days == 0 {
								return failr(r, fmt.Sprintf("PASS_MAX_DAYS is %d (STIG requires ≤ 60)", days),
									"set PASS_MAX_DAYS 60 in /etc/login.defs")
							}
						}
						return pass(r)
					}
				}
				return failr(r, "PASS_MAX_DAYS not set",
					"add PASS_MAX_DAYS 60 to /etc/login.defs")
			}},

		// V-238382: Minimum password age (STIG-specific)
		{ID: "V-238382", Framework: "STIG", Level: 1, Section: "Auth",
			Description: "The Ubuntu OS must enforce a minimum 1-day password age",
			Check: func(_ models.SecurityInfo, _ models.KernelSecurityInfo) models.CISResult {
				r := ruleByID("V-238382")
				data, err := os.ReadFile("/etc/login.defs") // #nosec G304
				if err != nil {
					return skipr(r, "could not read /etc/login.defs")
				}
				for _, line := range strings.Split(string(data), "\n") {
					if strings.HasPrefix(strings.TrimSpace(line), "#") {
						continue
					}
					if strings.HasPrefix(line, "PASS_MIN_DAYS") {
						fields := strings.Fields(line)
						if len(fields) >= 2 {
							days := 0
							fmt.Sscanf(fields[1], "%d", &days) //nolint:errcheck
							if days < 1 {
								return failr(r, fmt.Sprintf("PASS_MIN_DAYS is %d (must be ≥ 1)", days),
									"set PASS_MIN_DAYS 1 in /etc/login.defs")
							}
						}
						return pass(r)
					}
				}
				return failr(r, "PASS_MIN_DAYS not set in /etc/login.defs",
					"add PASS_MIN_DAYS 1 to /etc/login.defs")
			}},

		// V-238383: Password warning age (STIG-specific)
		{ID: "V-238383", Framework: "STIG", Level: 1, Section: "Auth",
			Description: "The Ubuntu OS must warn users 7 days before password expiry",
			Check: func(_ models.SecurityInfo, _ models.KernelSecurityInfo) models.CISResult {
				r := ruleByID("V-238383")
				data, err := os.ReadFile("/etc/login.defs") // #nosec G304
				if err != nil {
					return skipr(r, "could not read /etc/login.defs")
				}
				for _, line := range strings.Split(string(data), "\n") {
					if strings.HasPrefix(strings.TrimSpace(line), "#") {
						continue
					}
					if strings.HasPrefix(line, "PASS_WARN_AGE") {
						fields := strings.Fields(line)
						if len(fields) >= 2 {
							days := 0
							fmt.Sscanf(fields[1], "%d", &days) //nolint:errcheck
							if days < 7 {
								return failr(r, fmt.Sprintf("PASS_WARN_AGE is %d (must be ≥ 7)", days),
									"set PASS_WARN_AGE 7 in /etc/login.defs")
							}
						}
						return pass(r)
					}
				}
				return failr(r, "PASS_WARN_AGE not set in /etc/login.defs",
					"add PASS_WARN_AGE 7 to /etc/login.defs")
			}},
	}
}

// checkSysctl reads a /proc/sys path and compares to wantVal.
func checkSysctl(r Rule, path, wantVal, finding, fix string) models.CISResult {
	data, err := os.ReadFile(path) // #nosec G304 -- hardcoded /proc paths
	if err != nil {
		return skipr(r, fmt.Sprintf("could not read %s", path))
	}
	if strings.TrimSpace(string(data)) != wantVal {
		return failr(r, finding, fix)
	}
	return pass(r)
}

// checkFilePerm fails when the file carries any permission bit beyond those
// allowed by maxMode. It must test the bitmask, not magnitude: a numeric
// comparison (perm > maxMode) wrongly PASSES modes that are numerically smaller
// yet add a forbidden bit — e.g. /etc/shadow at 0o604 (world-readable) is 388,
// below maxMode 0o640 (416), so `> maxMode` is false and the world-read slips
// through. `perm &^ maxMode` isolates exactly the disallowed bits.
func checkFilePerm(r Rule, path string, maxMode os.FileMode, fix string) models.CISResult {
	fi, err := os.Stat(path) // #nosec G304 -- hardcoded system paths
	if err != nil {
		return skipr(r, fmt.Sprintf("%s not found", path))
	}
	if fi.Mode().Perm()&^maxMode != 0 {
		return failr(r, fmt.Sprintf("%s mode is %o (max %o)", path, fi.Mode().Perm(), maxMode), fix)
	}
	return pass(r)
}

// ruleByID returns the Rule struct for the given ID by scanning CISRules.
// Must be called only from within a Check function (after init completes).
func ruleByID(id string) Rule {
	for _, r := range CISRules {
		if r.ID == id {
			return r
		}
	}
	return Rule{ID: id, Framework: "CIS", Description: id}
}

// Evaluate runs all matching rules and returns a CISReport.
// When stig=true, results are presented with STIG IDs and descriptions.
func Evaluate(sec models.SecurityInfo, ks models.KernelSecurityInfo, level int, stig bool) models.CISReport {
	framework := "CIS"
	if stig {
		framework = "STIG"
	}
	report := models.CISReport{Framework: framework}

	for _, rule := range CISRules {
		if rule.Level > level {
			continue
		}
		// Filter by framework: run CIS rules always; run STIG rules only in STIG mode;
		// run BOTH rules always.
		if stig {
			if rule.Framework == "CIS" {
				continue // CIS-only rule — skip in STIG mode
			}
		} else {
			if rule.Framework == "STIG" {
				continue // STIG-only rule — skip in CIS mode
			}
		}

		result := rule.Check(sec, ks)

		// In STIG mode, swap in STIG ID and description where available
		if stig && rule.StigID != "" {
			result.ID = rule.StigID
			result.Framework = "STIG"
			if rule.StigDescription != "" {
				result.Description = rule.StigDescription
			}
		}

		report.Results = append(report.Results, result)
		switch result.Status {
		case models.CISPass:
			report.Pass++
		case models.CISFail:
			report.Fail++
		case models.CISManual:
			report.Manual++
		case models.CISNotApplicable:
			report.NA++
		case models.CISSkipped:
			report.Skipped++
		}
	}
	return report
}
