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

		{ID: "5.2.1", Framework: "CIS", Level: 1, Section: "SSH",
			Description: "Ensure permissions on /etc/ssh/sshd_config are configured (0600)",
			Check: func(sec models.SecurityInfo, _ models.KernelSecurityInfo) models.CISResult {
				r := ruleByID("5.2.1")
				fi, err := os.Stat("/etc/ssh/sshd_config")
				if err != nil {
					return skipr(r, "sshd_config not found")
				}
				if fi.Mode().Perm() > 0o600 {
					return failr(r, fmt.Sprintf("sshd_config mode %o", fi.Mode().Perm()),
						"chmod 600 /etc/ssh/sshd_config")
				}
				return pass(r)
			}},

		{ID: "5.2.2", Framework: "CIS", Level: 1, Section: "SSH",
			Description: "Ensure SSH access is limited (AllowUsers or AllowGroups set)",
			Check: func(sec models.SecurityInfo, _ models.KernelSecurityInfo) models.CISResult {
				r := ruleByID("5.2.2")
				if len(sec.SSHAllowUsers) == 0 && len(sec.SSHAllowGroups) == 0 {
					return failr(r, "AllowUsers and AllowGroups not configured",
						"set AllowUsers or AllowGroups in /etc/ssh/sshd_config")
				}
				return pass(r)
			}},

		{ID: "5.2.5", Framework: "CIS", Level: 1, Section: "SSH",
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

		{ID: "5.2.6", Framework: "CIS", Level: 1, Section: "SSH",
			Description: "Ensure SSH X11 forwarding is disabled",
			Check: func(sec models.SecurityInfo, _ models.KernelSecurityInfo) models.CISResult {
				r := ruleByID("5.2.6")
				if sec.SSHX11Forwarding {
					return failr(r, "X11Forwarding yes", "set X11Forwarding no in /etc/ssh/sshd_config")
				}
				return pass(r)
			}},

		{ID: "5.2.7", Framework: "CIS", Level: 1, Section: "SSH",
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

		{ID: "5.2.8", Framework: "CIS", Level: 1, Section: "SSH",
			Description: "Ensure SSH IgnoreRhosts is enabled",
			Check: func(sec models.SecurityInfo, _ models.KernelSecurityInfo) models.CISResult {
				r := ruleByID("5.2.8")
				if !sec.SSHIgnoreRhosts {
					return failr(r, "IgnoreRhosts is disabled",
						"set IgnoreRhosts yes in /etc/ssh/sshd_config")
				}
				return pass(r)
			}},

		{ID: "5.2.9", Framework: "CIS", Level: 1, Section: "SSH",
			Description: "Ensure SSH HostbasedAuthentication is disabled",
			Check: func(sec models.SecurityInfo, _ models.KernelSecurityInfo) models.CISResult {
				r := ruleByID("5.2.9")
				if sec.SSHHostbasedAuth {
					return failr(r, "HostbasedAuthentication is enabled",
						"set HostbasedAuthentication no in /etc/ssh/sshd_config")
				}
				return pass(r)
			}},

		{ID: "5.2.10", Framework: "CIS", Level: 1, Section: "SSH",
			Description: "Ensure SSH root login is disabled",
			Check: func(sec models.SecurityInfo, _ models.KernelSecurityInfo) models.CISResult {
				r := ruleByID("5.2.10")
				if sec.SSHPermitRoot {
					return failr(r, "PermitRootLogin is not 'no' or 'prohibit-password'",
						"set PermitRootLogin no in /etc/ssh/sshd_config")
				}
				return pass(r)
			}},

		{ID: "5.2.11", Framework: "CIS", Level: 1, Section: "SSH",
			Description: "Ensure SSH PermitEmptyPasswords is disabled",
			Check: func(sec models.SecurityInfo, _ models.KernelSecurityInfo) models.CISResult {
				r := ruleByID("5.2.11")
				if sec.SSHPermitEmptyPwd {
					return failr(r, "PermitEmptyPasswords yes",
						"set PermitEmptyPasswords no in /etc/ssh/sshd_config")
				}
				return pass(r)
			}},

		{ID: "5.2.12", Framework: "CIS", Level: 1, Section: "SSH",
			Description: "Ensure SSH PermitUserEnvironment is disabled",
			Check: func(sec models.SecurityInfo, _ models.KernelSecurityInfo) models.CISResult {
				r := ruleByID("5.2.12")
				if sec.SSHPermitUserEnv {
					return failr(r, "PermitUserEnvironment yes — users can override PATH/LD_PRELOAD",
						"set PermitUserEnvironment no in /etc/ssh/sshd_config")
				}
				return pass(r)
			}},

		{ID: "5.2.13", Framework: "CIS", Level: 1, Section: "SSH",
			Description: "Ensure SSH idle timeout is configured (ClientAliveInterval > 0)",
			Check: func(sec models.SecurityInfo, _ models.KernelSecurityInfo) models.CISResult {
				r := ruleByID("5.2.13")
				if sec.SSHClientAliveInterval == 0 {
					return failr(r, "ClientAliveInterval not set — sessions never time out",
						"set ClientAliveInterval 300 and ClientAliveCountMax 3 in /etc/ssh/sshd_config")
				}
				return pass(r)
			}},

		{ID: "5.2.14", Framework: "CIS", Level: 1, Section: "SSH",
			Description: "Ensure SSH LoginGraceTime is 60 seconds or less",
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

		{ID: "5.2.15", Framework: "CIS", Level: 1, Section: "SSH",
			Description: "Ensure SSH warning banner is configured",
			Check: func(sec models.SecurityInfo, _ models.KernelSecurityInfo) models.CISResult {
				r := ruleByID("5.2.15")
				if sec.SSHBanner == "" || strings.EqualFold(sec.SSHBanner, "none") {
					return failr(r, "Banner not configured",
						"set Banner /etc/issue.net in /etc/ssh/sshd_config")
				}
				return pass(r)
			}},

		{ID: "5.2.17", Framework: "CIS", Level: 1, Section: "SSH",
			Description: "Ensure SSH AllowTcpForwarding is disabled",
			Check: func(sec models.SecurityInfo, _ models.KernelSecurityInfo) models.CISResult {
				r := ruleByID("5.2.17")
				if sec.SSHTCPForwarding {
					return failr(r, "AllowTcpForwarding yes — can be used to pivot through this host",
						"set AllowTcpForwarding no in /etc/ssh/sshd_config")
				}
				return pass(r)
			}},

		{ID: "5.2.18", Framework: "CIS", Level: 1, Section: "SSH",
			Description: "Ensure SSH MaxStartups is configured",
			Check: func(sec models.SecurityInfo, _ models.KernelSecurityInfo) models.CISResult {
				r := ruleByID("5.2.18")
				if sec.SSHMaxStartups == "" {
					return failr(r, "MaxStartups not set (default allows 100 unauthenticated connections)",
						"set MaxStartups 10:30:60 in /etc/ssh/sshd_config")
				}
				return pass(r)
			}},

		{ID: "5.2.19", Framework: "CIS", Level: 1, Section: "SSH",
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

		{ID: "3.1.1", Framework: "CIS", Level: 1, Section: "Network",
			Description: "Ensure IP forwarding is disabled",
			Check: func(_ models.SecurityInfo, _ models.KernelSecurityInfo) models.CISResult {
				r := ruleByID("3.1.1")
				return checkSysctl(r, "/proc/sys/net/ipv4/ip_forward", "0",
					"net.ipv4.ip_forward=0 is not set — IP forwarding is on",
					"sysctl -w net.ipv4.ip_forward=0 && add to /etc/sysctl.d/99-cis.conf")
			}},

		{ID: "3.2.1", Framework: "CIS", Level: 1, Section: "Network",
			Description: "Ensure source routed packets are not accepted",
			Check: func(_ models.SecurityInfo, _ models.KernelSecurityInfo) models.CISResult {
				r := ruleByID("3.2.1")
				return checkSysctl(r, "/proc/sys/net/ipv4/conf/all/accept_source_route", "0",
					"accept_source_route is 1 — source routed packets accepted",
					"sysctl -w net.ipv4.conf.all.accept_source_route=0")
			}},

		{ID: "3.2.2", Framework: "CIS", Level: 1, Section: "Network",
			Description: "Ensure ICMP redirects are not accepted",
			Check: func(_ models.SecurityInfo, _ models.KernelSecurityInfo) models.CISResult {
				r := ruleByID("3.2.2")
				return checkSysctl(r, "/proc/sys/net/ipv4/conf/all/accept_redirects", "0",
					"accept_redirects is 1 — ICMP redirects accepted",
					"sysctl -w net.ipv4.conf.all.accept_redirects=0")
			}},

		{ID: "3.2.4", Framework: "CIS", Level: 1, Section: "Network",
			Description: "Ensure suspicious packets are logged (log_martians)",
			Check: func(_ models.SecurityInfo, _ models.KernelSecurityInfo) models.CISResult {
				r := ruleByID("3.2.4")
				return checkSysctl(r, "/proc/sys/net/ipv4/conf/all/log_martians", "1",
					"log_martians is 0 — martian packets not logged",
					"sysctl -w net.ipv4.conf.all.log_martians=1")
			}},

		// ── 4.x Logging and Auditing ──────────────────────────────────────────

		{ID: "4.1.1", Framework: "CIS", Level: 1, Section: "Audit",
			Description: "Ensure auditd is installed and running",
			Check: func(sec models.SecurityInfo, _ models.KernelSecurityInfo) models.CISResult {
				r := ruleByID("4.1.1")
				if sec.AuditRules == -1 {
					return failr(r, "auditd not installed or not running",
						"apt install auditd && systemctl enable --now auditd")
				}
				return pass(r)
			}},

		{ID: "4.1.2", Framework: "CIS", Level: 1, Section: "Audit",
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

		{ID: "5.4.1", Framework: "CIS", Level: 1, Section: "Auth",
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

		{ID: "6.1.1", Framework: "CIS", Level: 1, Section: "Files",
			Description: "Ensure /etc/passwd permissions are 644 or stricter",
			Check: func(_ models.SecurityInfo, _ models.KernelSecurityInfo) models.CISResult {
				r := ruleByID("6.1.1")
				return checkFilePerm(r, "/etc/passwd", 0o644, "chmod 644 /etc/passwd")
			}},

		{ID: "6.1.2", Framework: "CIS", Level: 1, Section: "Files",
			Description: "Ensure /etc/shadow permissions are 000 or 640",
			Check: func(_ models.SecurityInfo, _ models.KernelSecurityInfo) models.CISResult {
				r := ruleByID("6.1.2")
				return checkFilePerm(r, "/etc/shadow", 0o640, "chmod 000 /etc/shadow")
			}},

		{ID: "6.1.3", Framework: "CIS", Level: 1, Section: "Files",
			Description: "Ensure /etc/group permissions are 644 or stricter",
			Check: func(_ models.SecurityInfo, _ models.KernelSecurityInfo) models.CISResult {
				r := ruleByID("6.1.3")
				return checkFilePerm(r, "/etc/group", 0o644, "chmod 644 /etc/group")
			}},

		{ID: "6.2.2", Framework: "CIS", Level: 1, Section: "Users",
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

		{ID: "6.2.3", Framework: "CIS", Level: 1, Section: "Users",
			Description: "Ensure root is the only UID 0 account",
			Check: func(sec models.SecurityInfo, _ models.KernelSecurityInfo) models.CISResult {
				r := ruleByID("6.2.3")
				if len(sec.UID0Users) > 0 {
					return failr(r, fmt.Sprintf("UID 0 accounts: %s", strings.Join(sec.UID0Users, ", ")),
						"lock or remove these accounts: passwd -l <user>")
				}
				return pass(r)
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

// checkFilePerm checks that a file's permissions are <= maxMode.
func checkFilePerm(r Rule, path string, maxMode os.FileMode, fix string) models.CISResult {
	fi, err := os.Stat(path) // #nosec G304 -- hardcoded system paths
	if err != nil {
		return skipr(r, fmt.Sprintf("%s not found", path))
	}
	if fi.Mode().Perm() > maxMode {
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

// Evaluate runs all rules at or below level and returns a CISReport.
func Evaluate(sec models.SecurityInfo, ks models.KernelSecurityInfo, level int, framework string) models.CISReport {
	report := models.CISReport{Framework: framework}
	for _, rule := range CISRules {
		if rule.Level > level {
			continue
		}
		if framework != "ALL" && !strings.EqualFold(rule.Framework, framework) {
			continue
		}
		result := rule.Check(sec, ks)
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
