package cis

import (
	"fmt"
	"os"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"

	"github.com/keyorixhq/dashdiag/internal/models"
)

const (
	cisBenchBOTH      = "BOTH"
	cisCatSSH         = "SSH"
	cisBenchSTIG      = "STIG"
	cisCatNetwork     = "Network"
	cisCatServices    = "Services"
	cisCatMAC         = "MAC"
	cisCatAuth        = "Auth"
	cisCatFiles       = "Files"
	cisBenchCIS       = "CIS"
	cisRuleSSH52      = "5.2.1"
	cisRuleAudit41    = "4.1.1"
	stigPassMaxDaysID = "V-238380" //nolint:gosec // G101: STIG rule identifier, not a credential
)

// parseMaxStartups parses an sshd MaxStartups value ("start:rate:full" or a bare
// "start") into its start and full limits. A bare value has no random-drop
// throttling, so full == start. ok is false when the value can't be parsed.
func parseMaxStartups(v string) (start, full int, ok bool) {
	parts := strings.Split(strings.TrimSpace(v), ":")
	s, err := strconv.Atoi(parts[0])
	if err != nil {
		return 0, 0, false
	}
	if len(parts) < 3 {
		return s, s, true
	}
	f, err := strconv.Atoi(parts[2])
	if err != nil {
		return 0, 0, false
	}
	return s, f, true
}

// CISRules is the full benchmark rule set: CIS Ubuntu 22.04 LTS L1+L2
// covering filesystem (1.x), kernel hardening (1.5.x), bootloader (1.4.x), banners (1.7.x),
// services (2.x incl. legacy clients 2.2.x and server daemons 2.3.x), SSH (5.2.x),
// cron (5.1.x), network (3.x), audit (4.x), auth (5.x), files (6.x).
var CISRules []Rule

func init() {
	CISRules = buildRules()
}

//nolint:cyclop,funlen // rule registry — each entry is a self-contained check, splitting would harm readability
func buildRules() []Rule { // NOSONAR — flat rule registry; CC comes from entry count, not logic branches
	return []Rule{

		// ── 1.5 Additional Process Hardening ─────────────────────────────────

		{ID: "1.5.1", Framework: cisBenchCIS, Level: 1, Section: "Kernel",
			Description: "Ensure ASLR is enabled (kernel.randomize_va_space=2)",
			Check: func(_ models.SecurityInfo, _ models.KernelSecurityInfo) models.CISResult {
				r := ruleByID("1.5.1")
				return checkSysctl(r, "/proc/sys/kernel/randomize_va_space", "2",
					"ASLR not fully enabled (randomize_va_space != 2)",
					"sysctl -w kernel.randomize_va_space=2 && echo 'kernel.randomize_va_space=2' >> /etc/sysctl.d/99-cis.conf")
			}},

		{ID: "1.5.4", Framework: cisBenchCIS, Level: 1, Section: "Kernel",
			Description: "Ensure core dumps are restricted (fs.suid_dumpable=0)",
			Check: func(_ models.SecurityInfo, _ models.KernelSecurityInfo) models.CISResult {
				r := ruleByID("1.5.4")
				return checkSysctl(r, "/proc/sys/fs/suid_dumpable", "0",
					"SUID core dumps not restricted (fs.suid_dumpable != 0)",
					"sysctl -w fs.suid_dumpable=0 && echo 'fs.suid_dumpable=0' >> /etc/sysctl.d/99-cis.conf")
			}},

		// ── 2.1 Time Synchronization ──────────────────────────────────────────

		{ID: "2.1.1", Framework: cisBenchCIS, Level: 1, Section: cisCatServices,
			Description: "Ensure a time synchronization daemon is installed",
			Check: func(_ models.SecurityInfo, _ models.KernelSecurityInfo) models.CISResult {
				r := ruleByID("2.1.1")
				configs := append(chronyCfgPaths, ntpCfgPath, timesyncdCfgPath)
				for _, cfg := range configs {
					if _, err := os.Stat(cfg); err == nil {
						return pass(r)
					}
				}
				return failr(r, "no time synchronization daemon installed",
					"install a time sync daemon")
			}},

		{ID: "2.1.2", Framework: cisBenchCIS, Level: 1, Section: cisCatServices,
			Description: "Ensure time synchronization daemon is configured",
			Check: func(_ models.SecurityInfo, _ models.KernelSecurityInfo) models.CISResult {
				r := ruleByID("2.1.2")
				// chrony (RHEL path, then Debian/Ubuntu path)
				for _, path := range chronyCfgPaths {
					data, err := os.ReadFile(path) // #nosec G304
					if err != nil {
						continue
					}
					for line := range strings.SplitSeq(string(data), "\n") {
						line = strings.TrimSpace(line)
						if strings.HasPrefix(line, "server") || strings.HasPrefix(line, "pool") {
							return pass(r)
						}
					}
					return failr(r, "chrony.conf has no server or pool directive",
						"add 'pool pool.ntp.org iburst' to chrony.conf and restart chronyd")
				}
				// ntp
				if data, err := os.ReadFile(ntpCfgPath); err == nil { // #nosec G304
					for line := range strings.SplitSeq(string(data), "\n") {
						if strings.HasPrefix(strings.TrimSpace(line), "server") {
							return pass(r)
						}
					}
					return failr(r, "ntp.conf has no server directive",
						"add server directives to /etc/ntp.conf and restart ntp")
				}
				// systemd-timesyncd: uses compiled-in fallback NTP pool; presence is sufficient
				if _, err := os.Stat(timesyncdCfgPath); err == nil {
					return pass(r)
				}
				return skipr(r, "no time sync daemon config found — check rule 2.1.1")
			}},

		// ── 2.2 Legacy Service Clients ───────────────────────────────────────
		// CIS L1: these clients use cleartext/insecure protocols and must not be
		// present on a hardened server. A binary at any known path means installed.

		{ID: "2.2.1", Framework: cisBenchCIS, Level: 1, Section: cisCatServices,
			Description: "Ensure NIS client is not installed",
			Check: func(_ models.SecurityInfo, _ models.KernelSecurityInfo) models.CISResult {
				return checkServiceNotInstalled(ruleByID("2.2.1"), nisBinPaths,
					"remove NIS client: apt purge nis / dnf remove ypbind")
			}},

		{ID: "2.2.2", Framework: cisBenchCIS, Level: 1, Section: cisCatServices,
			Description: "Ensure rsh client is not installed",
			Check: func(_ models.SecurityInfo, _ models.KernelSecurityInfo) models.CISResult {
				return checkServiceNotInstalled(ruleByID("2.2.2"), rshBinPaths,
					"remove rsh client: apt purge rsh-client / dnf remove rsh")
			}},

		{ID: "2.2.3", Framework: cisBenchCIS, Level: 1, Section: cisCatServices,
			Description: "Ensure talk client is not installed",
			Check: func(_ models.SecurityInfo, _ models.KernelSecurityInfo) models.CISResult {
				return checkServiceNotInstalled(ruleByID("2.2.3"), talkBinPaths,
					"remove talk: apt purge talk / dnf remove talk")
			}},

		{ID: "2.2.4", Framework: cisBenchCIS, Level: 1, Section: cisCatServices,
			Description: "Ensure telnet client is not installed",
			Check: func(_ models.SecurityInfo, _ models.KernelSecurityInfo) models.CISResult {
				return checkServiceNotInstalled(ruleByID("2.2.4"), telnetBinPaths,
					"remove telnet: apt purge telnet / dnf remove telnet")
			}},

		// ── 2.3 Server Daemons Not Installed ─────────────────────────────────
		// These daemons are not needed on a general-purpose server and increase
		// attack surface. Binary presence → service is installed → FAIL.

		{ID: "2.3.1", Framework: cisBenchCIS, Level: 1, Section: cisCatServices,
			Description: "Ensure Xorg X11 server is not installed",
			Check: func(_ models.SecurityInfo, _ models.KernelSecurityInfo) models.CISResult {
				return checkServiceNotInstalled(ruleByID("2.3.1"), xorgBinPaths,
					"remove Xorg: apt purge xserver-xorg / dnf remove xorg-x11-server-Xorg")
			}},

		{ID: "2.3.2", Framework: cisBenchCIS, Level: 1, Section: cisCatServices,
			Description: "Ensure Avahi server is not installed",
			Check: func(_ models.SecurityInfo, _ models.KernelSecurityInfo) models.CISResult {
				return checkServiceNotInstalled(ruleByID("2.3.2"), avahiBinPaths,
					"remove Avahi: apt purge avahi-daemon / dnf remove avahi")
			}},

		{ID: "2.3.3", Framework: cisBenchCIS, Level: 1, Section: cisCatServices,
			Description: "Ensure CUPS printing server is not installed",
			Check: func(_ models.SecurityInfo, _ models.KernelSecurityInfo) models.CISResult {
				return checkServiceNotInstalled(ruleByID("2.3.3"), cupsBinPaths,
					"remove CUPS: apt purge cups / dnf remove cups")
			}},

		{ID: "2.3.4", Framework: cisBenchCIS, Level: 1, Section: cisCatServices,
			Description: "Ensure DHCP server is not installed",
			Check: func(_ models.SecurityInfo, _ models.KernelSecurityInfo) models.CISResult {
				return checkServiceNotInstalled(ruleByID("2.3.4"), dhcpBinPaths,
					"remove DHCP server: apt purge isc-dhcp-server / dnf remove dhcp-server")
			}},

		{ID: "2.3.5", Framework: cisBenchCIS, Level: 1, Section: cisCatServices,
			Description: "Ensure LDAP server is not installed",
			Check: func(_ models.SecurityInfo, _ models.KernelSecurityInfo) models.CISResult {
				return checkServiceNotInstalled(ruleByID("2.3.5"), slapdBinPaths,
					"remove LDAP server: apt purge slapd / dnf remove openldap-servers")
			}},

		{ID: "2.3.6", Framework: cisBenchCIS, Level: 1, Section: cisCatServices,
			Description: "Ensure NFS server is not installed",
			Check: func(_ models.SecurityInfo, _ models.KernelSecurityInfo) models.CISResult {
				return checkServiceNotInstalled(ruleByID("2.3.6"), nfsBinPaths,
					"remove NFS: apt purge nfs-kernel-server / dnf remove nfs-utils")
			}},

		{ID: "2.3.7", Framework: cisBenchCIS, Level: 1, Section: cisCatServices,
			Description: "Ensure DNS server is not installed",
			Check: func(_ models.SecurityInfo, _ models.KernelSecurityInfo) models.CISResult {
				return checkServiceNotInstalled(ruleByID("2.3.7"), namedBinPaths,
					"remove BIND/named: apt purge bind9 / dnf remove bind")
			}},

		{ID: "2.3.8", Framework: cisBenchCIS, Level: 1, Section: cisCatServices,
			Description: "Ensure FTP server is not installed",
			Check: func(_ models.SecurityInfo, _ models.KernelSecurityInfo) models.CISResult {
				return checkServiceNotInstalled(ruleByID("2.3.8"), ftpBinPaths,
					"remove FTP server: apt purge vsftpd / dnf remove vsftpd")
			}},

		{ID: "2.3.9", Framework: cisBenchCIS, Level: 1, Section: cisCatServices,
			Description: "Ensure HTTP server is not installed",
			Check: func(_ models.SecurityInfo, _ models.KernelSecurityInfo) models.CISResult {
				return checkServiceNotInstalled(ruleByID("2.3.9"), httpBinPaths,
					"remove HTTP server: apt purge apache2 nginx / dnf remove httpd nginx")
			}},

		{ID: "2.3.10", Framework: cisBenchCIS, Level: 1, Section: cisCatServices,
			Description: "Ensure IMAP and POP3 server is not installed",
			Check: func(_ models.SecurityInfo, _ models.KernelSecurityInfo) models.CISResult {
				return checkServiceNotInstalled(ruleByID("2.3.10"), imapBinPaths,
					"remove Dovecot: apt purge dovecot-imapd dovecot-pop3d / dnf remove dovecot")
			}},

		{ID: "2.3.11", Framework: cisBenchCIS, Level: 1, Section: cisCatServices,
			Description: "Ensure Samba server is not installed",
			Check: func(_ models.SecurityInfo, _ models.KernelSecurityInfo) models.CISResult {
				return checkServiceNotInstalled(ruleByID("2.3.11"), sambaBinPaths,
					"remove Samba: apt purge samba / dnf remove samba")
			}},

		{ID: "2.3.12", Framework: cisBenchCIS, Level: 1, Section: cisCatServices,
			Description: "Ensure HTTP proxy server is not installed",
			Check: func(_ models.SecurityInfo, _ models.KernelSecurityInfo) models.CISResult {
				return checkServiceNotInstalled(ruleByID("2.3.12"), squidBinPaths,
					"remove Squid: apt purge squid / dnf remove squid")
			}},

		{ID: "2.3.13", Framework: cisBenchCIS, Level: 1, Section: cisCatServices,
			Description: "Ensure SNMP server is not installed",
			Check: func(_ models.SecurityInfo, _ models.KernelSecurityInfo) models.CISResult {
				return checkServiceNotInstalled(ruleByID("2.3.13"), snmpBinPaths,
					"remove SNMP: apt purge snmpd / dnf remove net-snmp")
			}},

		// ── 5.2 SSH Server Configuration ─────────────────────────────────────

		{ID: cisRuleSSH52, StigID: "V-238201", Framework: cisBenchBOTH, Level: 1, Section: cisCatSSH,
			Description:     "Ensure permissions on /etc/ssh/sshd_config are configured (0600)",
			StigDescription: "The SSH daemon configuration file must have mode 0600 or less permissive",
			Check: func(sec models.SecurityInfo, _ models.KernelSecurityInfo) models.CISResult {
				r := ruleByID(cisRuleSSH52)
				fi, err := os.Stat(sshdConfigPath)
				if err != nil {
					return skipr(r, "sshd_config not found")
				}
				if fi.Mode().Perm()&^0o600 != 0 {
					return failr(r, fmt.Sprintf("sshd_config mode %o", fi.Mode().Perm()),
						"chmod 600 /etc/ssh/sshd_config")
				}
				return pass(r)
			}},

		{ID: "5.2.2", StigID: "V-238202", Framework: cisBenchBOTH, Level: 1, Section: cisCatSSH,
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
			StigDescription: "The SSH daemon must use an approved log level", Framework: cisBenchBOTH, Level: 1, Section: cisCatSSH,
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
			StigDescription: "The SSH daemon must not allow X11 forwarding", Framework: cisBenchBOTH, Level: 1, Section: cisCatSSH,
			Description: "Ensure SSH X11 forwarding is disabled",
			Check: func(sec models.SecurityInfo, _ models.KernelSecurityInfo) models.CISResult {
				r := ruleByID("5.2.6")
				if sec.SSHX11Forwarding {
					return failr(r, "X11Forwarding yes", "set X11Forwarding no in /etc/ssh/sshd_config")
				}
				return pass(r)
			}},

		{ID: "5.2.7", StigID: "V-238217",
			StigDescription: "The SSH daemon must limit authentication attempts", Framework: cisBenchBOTH, Level: 1, Section: cisCatSSH,
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
			StigDescription: "The SSH daemon must ignore .rhosts files", Framework: cisBenchBOTH, Level: 1, Section: cisCatSSH,
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
			StigDescription: "The SSH daemon must not allow host-based authentication", Framework: cisBenchBOTH, Level: 1, Section: cisCatSSH,
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
			StigDescription: "The SSH daemon must not allow root logins", Framework: cisBenchBOTH, Level: 1, Section: cisCatSSH,
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
			StigDescription: "The SSH daemon must not allow empty passwords", Framework: cisBenchBOTH, Level: 1, Section: cisCatSSH,
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
			StigDescription: "The SSH daemon must not permit user environment variables", Framework: cisBenchBOTH, Level: 1, Section: cisCatSSH,
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
			StigDescription: "The SSH daemon must set a timeout interval on idle sessions", Framework: cisBenchBOTH, Level: 1, Section: cisCatSSH,
			Description: "Ensure SSH idle timeout is configured (ClientAliveInterval > 0)",
			Check: func(sec models.SecurityInfo, _ models.KernelSecurityInfo) models.CISResult {
				r := ruleByID("5.2.13")
				if sec.SSHClientAliveInterval == 0 {
					return failr(r, "ClientAliveInterval not set — sessions never time out",
						"set ClientAliveInterval 300 and ClientAliveCountMax 3 in /etc/ssh/sshd_config")
				}
				return pass(r)
			}},

		{ID: "5.2.14", StigID: "V-238206", Framework: cisBenchBOTH, Level: 1, Section: cisCatSSH,
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
			StigDescription: "The SSH daemon must display a login banner", Framework: cisBenchBOTH, Level: 1, Section: cisCatSSH,
			Description: "Ensure SSH warning banner is configured",
			Check: func(sec models.SecurityInfo, _ models.KernelSecurityInfo) models.CISResult {
				r := ruleByID("5.2.15")
				if sec.SSHBanner == "" || strings.EqualFold(sec.SSHBanner, "none") {
					return failr(r, "Banner not configured",
						"set Banner /etc/issue.net in /etc/ssh/sshd_config")
				}
				return pass(r)
			}},

		{ID: "5.2.16", Framework: cisBenchCIS, Level: 1, Section: cisCatSSH,
			Description: "Ensure SSH idle timeout interval is configured (ClientAliveInterval <= 900s)",
			Check: func(sec models.SecurityInfo, _ models.KernelSecurityInfo) models.CISResult {
				r := ruleByID("5.2.16")
				v := sec.SSHClientAliveInterval
				if v == 0 {
					return failr(r, "ClientAliveInterval not set — idle SSH sessions never expire",
						"set ClientAliveInterval 900 and ClientAliveCountMax 0 in /etc/ssh/sshd_config")
				}
				if v > 900 {
					return failr(r, fmt.Sprintf("ClientAliveInterval %ds exceeds 900s limit", v),
						"set ClientAliveInterval 900 in /etc/ssh/sshd_config")
				}
				return pass(r)
			}},

		{ID: "5.2.17", StigID: "V-238222",
			StigDescription: "The SSH daemon must not allow TCP port forwarding", Framework: cisBenchBOTH, Level: 1, Section: cisCatSSH,
			Description: "Ensure SSH AllowTcpForwarding is disabled",
			Check: func(sec models.SecurityInfo, _ models.KernelSecurityInfo) models.CISResult {
				r := ruleByID("5.2.17")
				if sec.SSHTCPForwarding {
					return failr(r, "AllowTcpForwarding yes — can be used to pivot through this host",
						"set AllowTcpForwarding no in /etc/ssh/sshd_config")
				}
				return pass(r)
			}},

		{ID: "5.2.18", StigID: "V-238223", Framework: cisBenchBOTH, Level: 1, Section: cisCatSSH,
			Description: "Ensure SSH MaxStartups is configured",
			Check: func(sec models.SecurityInfo, _ models.KernelSecurityInfo) models.CISResult {
				r := ruleByID("5.2.18")
				// `sshd -T` always emits MaxStartups (compiled default 10:30:100),
				// so presence alone is not compliance — the value must be within
				// CIS limits (start ≤ 10, full ≤ 60). The OpenSSH default 10:30:100
				// FAILS, so a presence-only check wrongly passed every stock host.
				if sec.SSHMaxStartups == "" {
					return failr(r, "MaxStartups not set (default 10:30:100 allows 100 unauthenticated connections)",
						"set MaxStartups 10:30:60 in /etc/ssh/sshd_config")
				}
				if start, full, ok := parseMaxStartups(sec.SSHMaxStartups); ok && (start > 10 || full > 60) {
					return failr(r, fmt.Sprintf("MaxStartups %s exceeds CIS limit (start ≤ 10, full ≤ 60)", sec.SSHMaxStartups),
						"set MaxStartups 10:30:60 in /etc/ssh/sshd_config")
				}
				return pass(r)
			}},

		{ID: "5.2.19", StigID: "V-238224", Framework: cisBenchBOTH, Level: 1, Section: cisCatSSH,
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
			StigDescription: "IP forwarding must be disabled", Framework: cisBenchBOTH, Level: 1, Section: cisCatNetwork,
			Description: "Ensure IP forwarding is disabled",
			Check: func(_ models.SecurityInfo, _ models.KernelSecurityInfo) models.CISResult {
				r := ruleByID("3.1.1")
				return checkSysctl(r, "/proc/sys/net/ipv4/ip_forward", "0",
					"net.ipv4.ip_forward=0 is not set — IP forwarding is on",
					"sysctl -w net.ipv4.ip_forward=0 && add to /etc/sysctl.d/99-cis.conf")
			}},

		{ID: "3.1.2", Framework: cisBenchCIS, Level: 1, Section: cisCatNetwork,
			Description: "Ensure packet redirect sending is disabled",
			Check: func(_ models.SecurityInfo, _ models.KernelSecurityInfo) models.CISResult {
				r := ruleByID("3.1.2")
				return checkSysctl(r, "/proc/sys/net/ipv4/conf/all/send_redirects", "0",
					"send_redirects is 1 — host can send ICMP redirects (man-in-the-middle risk)",
					"sysctl -w net.ipv4.conf.all.send_redirects=0 && sysctl -w net.ipv4.conf.default.send_redirects=0")
			}},

		{ID: "3.2.1", StigID: "V-238328",
			StigDescription: "Source routing must be disabled", Framework: cisBenchBOTH, Level: 1, Section: cisCatNetwork,
			Description: "Ensure source routed packets are not accepted",
			Check: func(_ models.SecurityInfo, _ models.KernelSecurityInfo) models.CISResult {
				r := ruleByID("3.2.1")
				return checkSysctl(r, "/proc/sys/net/ipv4/conf/all/accept_source_route", "0",
					"accept_source_route is 1 — source routed packets accepted",
					"sysctl -w net.ipv4.conf.all.accept_source_route=0")
			}},

		{ID: "3.2.2", StigID: "V-238329",
			StigDescription: "ICMP redirects must not be accepted", Framework: cisBenchBOTH, Level: 1, Section: cisCatNetwork,
			Description: "Ensure ICMP redirects are not accepted",
			Check: func(_ models.SecurityInfo, _ models.KernelSecurityInfo) models.CISResult {
				r := ruleByID("3.2.2")
				return checkSysctl(r, "/proc/sys/net/ipv4/conf/all/accept_redirects", "0",
					"accept_redirects is 1 — ICMP redirects accepted",
					"sysctl -w net.ipv4.conf.all.accept_redirects=0")
			}},

		{ID: "3.2.3", Framework: cisBenchCIS, Level: 1, Section: cisCatNetwork,
			Description: "Ensure secure ICMP redirects are not accepted",
			Check: func(_ models.SecurityInfo, _ models.KernelSecurityInfo) models.CISResult {
				r := ruleByID("3.2.3")
				return checkSysctl(r, "/proc/sys/net/ipv4/conf/all/secure_redirects", "0",
					"secure_redirects is 1 — ICMP redirects from gateways accepted without validation",
					"sysctl -w net.ipv4.conf.all.secure_redirects=0 && echo 'net.ipv4.conf.all.secure_redirects=0' >> /etc/sysctl.d/99-cis.conf")
			}},

		{ID: "3.2.4", StigID: "V-238331",
			StigDescription: "Suspicious packets must be logged", Framework: cisBenchBOTH, Level: 1, Section: cisCatNetwork,
			Description: "Ensure suspicious packets are logged (log_martians)",
			Check: func(_ models.SecurityInfo, _ models.KernelSecurityInfo) models.CISResult {
				r := ruleByID("3.2.4")
				return checkSysctl(r, "/proc/sys/net/ipv4/conf/all/log_martians", "1",
					"log_martians is 0 — martian packets not logged",
					"sysctl -w net.ipv4.conf.all.log_martians=1")
			}},

		// ── 1.3 Filesystem Integrity ─────────────────────────────────────────

		{ID: "1.3.1", Framework: cisBenchCIS, Level: 1, Section: "Filesystem",
			Description: "Ensure AIDE is installed",
			Check: func(sec models.SecurityInfo, _ models.KernelSecurityInfo) models.CISResult {
				r := ruleByID("1.3.1")
				if !sec.AIDEInstalled {
					// remediation is rewritten per package manager in Evaluate
					return failr(r, "AIDE (Advanced Intrusion Detection Environment) is not installed",
						aideInstallCmd("apt"))
				}
				return pass(r)
			}},

		{ID: "1.3.2", Framework: cisBenchCIS, Level: 1, Section: "Filesystem",
			Description: "Ensure filesystem integrity is regularly checked",
			Check: func(sec models.SecurityInfo, _ models.KernelSecurityInfo) models.CISResult {
				r := ruleByID("1.3.2")
				if !sec.AIDEInstalled {
					return skipr(r, "AIDE not installed — install first (rule 1.3.1)")
				}
				if !sec.AIDEDBExists {
					return failr(r, "AIDE database not initialized",
						"run: aide --init && mv /var/lib/aide/aide.db.new /var/lib/aide/aide.db")
				}
				if sec.AIDELastRunDays == -1 {
					return failr(r, "AIDE has never been run",
						"schedule: 0 5 * * * root /usr/bin/aide --check")
				}
				if sec.AIDELastRunDays > 7 {
					return failr(r, fmt.Sprintf("AIDE last ran %d days ago (threshold: 7 days)", sec.AIDELastRunDays),
						"schedule: 0 5 * * * root /usr/bin/aide --check")
				}
				return pass(r)
			}},

		// ── 1.4 Bootloader Configuration ─────────────────────────────────────
		// Scan known GRUB config paths (Ubuntu/Debian vs RHEL/Rocky); use the
		// first one found. SKIP when no GRUB config is found (e.g. UEFI-only or
		// non-GRUB systems that use systemd-boot).

		{ID: "1.4.1", Framework: cisBenchCIS, Level: 1, Section: "Filesystem",
			Description: "Ensure GRUB bootloader config is not world-readable (≤ 0600)",
			Check: func(_ models.SecurityInfo, _ models.KernelSecurityInfo) models.CISResult {
				r := ruleByID("1.4.1")
				for _, p := range grubCfgPaths {
					if _, err := os.Stat(p); err == nil {
						return checkFilePerm(r, p, 0o600, "chmod og-rwx "+p)
					}
				}
				return skipr(r, "grub.cfg not found at any known path (UEFI-only or non-GRUB system)")
			}},

		{ID: "1.4.2", Framework: cisBenchCIS, Level: 1, Section: "Filesystem",
			Description: "Ensure GRUB bootloader config is owned by root:root",
			Check: func(_ models.SecurityInfo, _ models.KernelSecurityInfo) models.CISResult {
				r := ruleByID("1.4.2")
				for _, p := range grubCfgPaths {
					if _, err := os.Stat(p); err == nil {
						return checkFileOwnerRootRoot(r, p, "chown root:root "+p)
					}
				}
				return skipr(r, "grub.cfg not found at any known path (UEFI-only or non-GRUB system)")
			}},

		// ── 1.1.1 Disable Unused Filesystems ─────────────────────────────────────

		{ID: "1.1.1.1", Framework: cisBenchCIS, Level: 1, Section: "Filesystem",
			Description: "Ensure mounting of cramfs filesystems is disabled",
			Check: func(_ models.SecurityInfo, _ models.KernelSecurityInfo) models.CISResult {
				return checkModuleDisabled(ruleByID("1.1.1.1"), "cramfs",
					"echo 'install cramfs /bin/true' > /etc/modprobe.d/cramfs.conf")
			}},

		{ID: "1.1.1.2", Framework: cisBenchCIS, Level: 1, Section: "Filesystem",
			Description: "Ensure mounting of freevxfs filesystems is disabled",
			Check: func(_ models.SecurityInfo, _ models.KernelSecurityInfo) models.CISResult {
				return checkModuleDisabled(ruleByID("1.1.1.2"), "freevxfs",
					"echo 'install freevxfs /bin/true' > /etc/modprobe.d/freevxfs.conf")
			}},

		{ID: "1.1.1.3", Framework: cisBenchCIS, Level: 1, Section: "Filesystem",
			Description: "Ensure mounting of jffs2 filesystems is disabled",
			Check: func(_ models.SecurityInfo, _ models.KernelSecurityInfo) models.CISResult {
				return checkModuleDisabled(ruleByID("1.1.1.3"), "jffs2",
					"echo 'install jffs2 /bin/true' > /etc/modprobe.d/jffs2.conf")
			}},

		{ID: "1.1.1.4", Framework: cisBenchCIS, Level: 1, Section: "Filesystem",
			Description: "Ensure mounting of hfs filesystems is disabled",
			Check: func(_ models.SecurityInfo, _ models.KernelSecurityInfo) models.CISResult {
				return checkModuleDisabled(ruleByID("1.1.1.4"), "hfs",
					"echo 'install hfs /bin/true' > /etc/modprobe.d/hfs.conf")
			}},

		{ID: "1.1.1.5", Framework: cisBenchCIS, Level: 1, Section: "Filesystem",
			Description: "Ensure mounting of hfsplus filesystems is disabled",
			Check: func(_ models.SecurityInfo, _ models.KernelSecurityInfo) models.CISResult {
				return checkModuleDisabled(ruleByID("1.1.1.5"), "hfsplus",
					"echo 'install hfsplus /bin/true' > /etc/modprobe.d/hfsplus.conf")
			}},

		{ID: "1.1.1.6", Framework: cisBenchCIS, Level: 2, Section: "Filesystem",
			Description: "Ensure mounting of squashfs filesystems is disabled",
			Check: func(_ models.SecurityInfo, _ models.KernelSecurityInfo) models.CISResult {
				return checkModuleDisabled(ruleByID("1.1.1.6"), "squashfs",
					"echo 'install squashfs /bin/true' > /etc/modprobe.d/squashfs.conf (disable only when snaps are not used)")
			}},

		{ID: "1.1.1.7", Framework: cisBenchCIS, Level: 2, Section: "Filesystem",
			Description: "Ensure mounting of udf filesystems is disabled",
			Check: func(_ models.SecurityInfo, _ models.KernelSecurityInfo) models.CISResult {
				return checkModuleDisabled(ruleByID("1.1.1.7"), "udf",
					"echo 'install udf /bin/true' > /etc/modprobe.d/udf.conf")
			}},

		// ── 1.1.2–1.1.14 Mount Point Options ─────────────────────────────────────
		// /proc/mounts is authoritative for active mount options. Rules SKIP when
		// the mount point is not a separate partition.

		{ID: "1.1.2", Framework: cisBenchCIS, Level: 1, Section: "Filesystem",
			Description: "Ensure /tmp is configured as a separate partition",
			Check: func(_ models.SecurityInfo, _ models.KernelSecurityInfo) models.CISResult {
				return checkSeparateMountPoint(ruleByID("1.1.2"), "/tmp",
					"add tmpfs /tmp tmpfs defaults,rw,nosuid,nodev,noexec 0 0 to /etc/fstab")
			}},

		{ID: "1.1.3", Framework: cisBenchCIS, Level: 1, Section: "Filesystem",
			Description: "Ensure nodev option set on /tmp partition",
			Check: func(_ models.SecurityInfo, _ models.KernelSecurityInfo) models.CISResult {
				return checkMountOption(ruleByID("1.1.3"), "/tmp", "nodev",
					"add 'nodev' to /tmp mount options in /etc/fstab")
			}},

		{ID: "1.1.4", Framework: cisBenchCIS, Level: 1, Section: "Filesystem",
			Description: "Ensure nosuid option set on /tmp partition",
			Check: func(_ models.SecurityInfo, _ models.KernelSecurityInfo) models.CISResult {
				return checkMountOption(ruleByID("1.1.4"), "/tmp", "nosuid",
					"add 'nosuid' to /tmp mount options in /etc/fstab")
			}},

		{ID: "1.1.5", Framework: cisBenchCIS, Level: 1, Section: "Filesystem",
			Description: "Ensure noexec option set on /tmp partition",
			Check: func(_ models.SecurityInfo, _ models.KernelSecurityInfo) models.CISResult {
				return checkMountOption(ruleByID("1.1.5"), "/tmp", "noexec",
					"add 'noexec' to /tmp mount options in /etc/fstab")
			}},

		{ID: "1.1.6", Framework: cisBenchCIS, Level: 1, Section: "Filesystem",
			Description: "Ensure nodev option set on /dev/shm partition",
			Check: func(_ models.SecurityInfo, _ models.KernelSecurityInfo) models.CISResult {
				return checkMountOption(ruleByID("1.1.6"), "/dev/shm", "nodev",
					"add 'nodev' to /dev/shm mount options in /etc/fstab")
			}},

		{ID: "1.1.7", Framework: cisBenchCIS, Level: 1, Section: "Filesystem",
			Description: "Ensure nosuid option set on /dev/shm partition",
			Check: func(_ models.SecurityInfo, _ models.KernelSecurityInfo) models.CISResult {
				return checkMountOption(ruleByID("1.1.7"), "/dev/shm", "nosuid",
					"add 'nosuid' to /dev/shm mount options in /etc/fstab")
			}},

		{ID: "1.1.8", Framework: cisBenchCIS, Level: 1, Section: "Filesystem",
			Description: "Ensure noexec option set on /dev/shm partition",
			Check: func(_ models.SecurityInfo, _ models.KernelSecurityInfo) models.CISResult {
				return checkMountOption(ruleByID("1.1.8"), "/dev/shm", "noexec",
					"add 'noexec' to /dev/shm mount options in /etc/fstab")
			}},

		{ID: "1.1.9", Framework: cisBenchCIS, Level: 1, Section: "Filesystem",
			Description: "Ensure nodev option set on /var/tmp partition",
			Check: func(_ models.SecurityInfo, _ models.KernelSecurityInfo) models.CISResult {
				return checkMountOption(ruleByID("1.1.9"), "/var/tmp", "nodev",
					"add 'nodev' to /var/tmp mount options in /etc/fstab")
			}},

		{ID: "1.1.10", Framework: cisBenchCIS, Level: 1, Section: "Filesystem",
			Description: "Ensure nosuid option set on /var/tmp partition",
			Check: func(_ models.SecurityInfo, _ models.KernelSecurityInfo) models.CISResult {
				return checkMountOption(ruleByID("1.1.10"), "/var/tmp", "nosuid",
					"add 'nosuid' to /var/tmp mount options in /etc/fstab")
			}},

		{ID: "1.1.11", Framework: cisBenchCIS, Level: 1, Section: "Filesystem",
			Description: "Ensure noexec option set on /var/tmp partition",
			Check: func(_ models.SecurityInfo, _ models.KernelSecurityInfo) models.CISResult {
				return checkMountOption(ruleByID("1.1.11"), "/var/tmp", "noexec",
					"add 'noexec' to /var/tmp mount options in /etc/fstab")
			}},

		{ID: "1.1.12", Framework: cisBenchCIS, Level: 2, Section: "Filesystem",
			Description: "Ensure /var/log directory is on its own filesystem",
			Check: func(_ models.SecurityInfo, _ models.KernelSecurityInfo) models.CISResult {
				return checkSeparateMountPoint(ruleByID("1.1.12"), "/var/log",
					"create a separate /var/log partition and add to /etc/fstab")
			}},

		{ID: "1.1.13", Framework: cisBenchCIS, Level: 2, Section: "Filesystem",
			Description: "Ensure /var/log/audit directory is on its own filesystem",
			Check: func(_ models.SecurityInfo, _ models.KernelSecurityInfo) models.CISResult {
				return checkSeparateMountPoint(ruleByID("1.1.13"), "/var/log/audit",
					"create a separate /var/log/audit partition and add to /etc/fstab")
			}},

		{ID: "1.1.14", Framework: cisBenchCIS, Level: 1, Section: "Filesystem",
			Description: "Ensure nodev option set on /home partition",
			Check: func(_ models.SecurityInfo, _ models.KernelSecurityInfo) models.CISResult {
				return checkMountOption(ruleByID("1.1.14"), "/home", "nodev",
					"add 'nodev' to /home mount options in /etc/fstab")
			}},

		{ID: "1.1.15", Framework: cisBenchCIS, Level: 2, Section: "Filesystem",
			Description: "Ensure nosuid option set on /home partition",
			Check: func(_ models.SecurityInfo, _ models.KernelSecurityInfo) models.CISResult {
				return checkMountOption(ruleByID("1.1.15"), "/home", "nosuid",
					"add 'nosuid' to /home mount options in /etc/fstab")
			}},

		{ID: "1.1.16", Framework: cisBenchCIS, Level: 2, Section: "Filesystem",
			Description: "Ensure noexec option set on /home partition",
			Check: func(_ models.SecurityInfo, _ models.KernelSecurityInfo) models.CISResult {
				return checkMountOption(ruleByID("1.1.16"), "/home", "noexec",
					"add 'noexec' to /home mount options in /etc/fstab")
			}},

		// ── 1.5.2 Prelink ─────────────────────────────────────────────────────────

		{ID: "1.5.2", Framework: cisBenchCIS, Level: 1, Section: "Kernel",
			Description: "Ensure prelink is not installed",
			Check: func(_ models.SecurityInfo, _ models.KernelSecurityInfo) models.CISResult {
				return checkServiceNotInstalled(ruleByID("1.5.2"), prelinkBinPaths,
					"apt purge prelink / dnf remove prelink")
			}},

		{ID: "1.5.3", Framework: cisBenchCIS, Level: 1, Section: "Kernel",
			Description: "Ensure address space layout randomization (ASLR) is enabled",
			Check: func(_ models.SecurityInfo, _ models.KernelSecurityInfo) models.CISResult {
				r := ruleByID("1.5.3")
				return checkSysctl(r, "/proc/sys/kernel/randomize_va_space", "2",
					"ASLR is disabled (randomize_va_space != 2)",
					"sysctl -w kernel.randomize_va_space=2 && echo 'kernel.randomize_va_space=2' >> /etc/sysctl.d/99-cis.conf")
			}},

		// ── 1.7 Warning Banners ───────────────────────────────────────────────

		{ID: "1.7.1", Framework: cisBenchCIS, Level: 1, Section: "Banners",
			Description: "Ensure /etc/motd is configured (no OS fingerprinting sequences)",
			Check: func(_ models.SecurityInfo, _ models.KernelSecurityInfo) models.CISResult {
				return checkBannerContent(ruleByID("1.7.1"), motdPath,
					"add a warning banner to /etc/motd — no \\s \\m \\r \\v \\u sequences")
			}},

		{ID: "1.7.2", Framework: cisBenchCIS, Level: 1, Section: "Banners",
			Description: "Ensure /etc/issue is configured (no OS fingerprinting sequences)",
			Check: func(_ models.SecurityInfo, _ models.KernelSecurityInfo) models.CISResult {
				return checkBannerContent(ruleByID("1.7.2"), issuePath,
					"add a warning banner to /etc/issue — no \\s \\m \\r \\v \\u sequences")
			}},

		{ID: "1.7.3", Framework: cisBenchCIS, Level: 1, Section: "Banners",
			Description: "Ensure /etc/issue.net is configured (no OS fingerprinting sequences)",
			Check: func(_ models.SecurityInfo, _ models.KernelSecurityInfo) models.CISResult {
				return checkBannerContent(ruleByID("1.7.3"), issueNetPath,
					"add a warning banner to /etc/issue.net — no \\s \\m \\r \\v \\u sequences")
			}},

		{ID: "1.7.4", Framework: cisBenchCIS, Level: 1, Section: "Banners",
			Description: "Ensure /etc/motd permissions are 644 or stricter",
			Check: func(_ models.SecurityInfo, _ models.KernelSecurityInfo) models.CISResult {
				return checkFilePerm(ruleByID("1.7.4"), motdPath, 0o644, "chmod 644 /etc/motd")
			}},

		{ID: "1.7.5", Framework: cisBenchCIS, Level: 1, Section: "Banners",
			Description: "Ensure /etc/issue permissions are 644 or stricter",
			Check: func(_ models.SecurityInfo, _ models.KernelSecurityInfo) models.CISResult {
				return checkFilePerm(ruleByID("1.7.5"), issuePath, 0o644, "chmod 644 /etc/issue")
			}},

		{ID: "1.7.6", Framework: cisBenchCIS, Level: 1, Section: "Banners",
			Description: "Ensure /etc/issue.net permissions are 644 or stricter",
			Check: func(_ models.SecurityInfo, _ models.KernelSecurityInfo) models.CISResult {
				return checkFilePerm(ruleByID("1.7.6"), issueNetPath, 0o644, "chmod 644 /etc/issue.net")
			}},

		{ID: "3.2.5", Framework: cisBenchCIS, Level: 1, Section: cisCatNetwork,
			Description: "Ensure broadcast ICMP requests are ignored",
			Check: func(_ models.SecurityInfo, _ models.KernelSecurityInfo) models.CISResult {
				r := ruleByID("3.2.5")
				return checkSysctl(r, "/proc/sys/net/ipv4/icmp_echo_ignore_broadcasts", "1",
					"icmp_echo_ignore_broadcasts is 0 — smurf amplification possible",
					"sysctl -w net.ipv4.icmp_echo_ignore_broadcasts=1 && echo 'net.ipv4.icmp_echo_ignore_broadcasts=1' >> /etc/sysctl.d/99-cis.conf")
			}},

		{ID: "3.2.6", Framework: cisBenchCIS, Level: 1, Section: cisCatNetwork,
			Description: "Ensure bogus ICMP responses are ignored",
			Check: func(_ models.SecurityInfo, _ models.KernelSecurityInfo) models.CISResult {
				r := ruleByID("3.2.6")
				return checkSysctl(r, "/proc/sys/net/ipv4/icmp_ignore_bogus_error_responses", "1",
					"icmp_ignore_bogus_error_responses is 0 — bogus ICMP error messages accepted",
					"sysctl -w net.ipv4.icmp_ignore_bogus_error_responses=1 && echo 'net.ipv4.icmp_ignore_bogus_error_responses=1' >> /etc/sysctl.d/99-cis.conf")
			}},

		{ID: "3.2.7", Framework: cisBenchCIS, Level: 1, Section: cisCatNetwork,
			Description: "Ensure Reverse Path Filtering is enabled (anti-spoofing)",
			Check: func(_ models.SecurityInfo, _ models.KernelSecurityInfo) models.CISResult {
				r := ruleByID("3.2.7")
				return checkSysctl(r, "/proc/sys/net/ipv4/conf/all/rp_filter", "1",
					"rp_filter is 0 — reverse path filtering disabled (IP spoofing possible)",
					"sysctl -w net.ipv4.conf.all.rp_filter=1 && sysctl -w net.ipv4.conf.default.rp_filter=1")
			}},

		{ID: "3.2.8", Framework: cisBenchCIS, Level: 1, Section: cisCatNetwork,
			Description: "Ensure TCP SYN cookies is enabled",
			Check: func(_ models.SecurityInfo, _ models.KernelSecurityInfo) models.CISResult {
				r := ruleByID("3.2.8")
				return checkSysctl(r, "/proc/sys/net/ipv4/tcp_syncookies", "1",
					"tcp_syncookies is 0 — SYN flood protection disabled",
					"sysctl -w net.ipv4.tcp_syncookies=1 && echo 'net.ipv4.tcp_syncookies=1' >> /etc/sysctl.d/99-cis.conf")
			}},

		// ── 3.4 Uncommon Network Protocols ───────────────────────────────────────
		// These kernel modules implement uncommon network protocols rarely needed
		// on servers. Disabling prevents them from being loaded on demand.

		{ID: "3.4.1", Framework: cisBenchCIS, Level: 2, Section: cisCatNetwork,
			Description: "Ensure DCCP is disabled",
			Check: func(_ models.SecurityInfo, _ models.KernelSecurityInfo) models.CISResult {
				return checkModuleDisabled(ruleByID("3.4.1"), "dccp",
					"echo 'install dccp /bin/true' > /etc/modprobe.d/dccp.conf")
			}},

		{ID: "3.4.2", Framework: cisBenchCIS, Level: 2, Section: cisCatNetwork,
			Description: "Ensure SCTP is disabled",
			Check: func(_ models.SecurityInfo, _ models.KernelSecurityInfo) models.CISResult {
				return checkModuleDisabled(ruleByID("3.4.2"), "sctp",
					"echo 'install sctp /bin/true' > /etc/modprobe.d/sctp.conf")
			}},

		{ID: "3.4.3", Framework: cisBenchCIS, Level: 2, Section: cisCatNetwork,
			Description: "Ensure RDS is disabled",
			Check: func(_ models.SecurityInfo, _ models.KernelSecurityInfo) models.CISResult {
				return checkModuleDisabled(ruleByID("3.4.3"), "rds",
					"echo 'install rds /bin/true' > /etc/modprobe.d/rds.conf")
			}},

		{ID: "3.4.4", Framework: cisBenchCIS, Level: 2, Section: cisCatNetwork,
			Description: "Ensure TIPC is disabled",
			Check: func(_ models.SecurityInfo, _ models.KernelSecurityInfo) models.CISResult {
				return checkModuleDisabled(ruleByID("3.4.4"), "tipc",
					"echo 'install tipc /bin/true' > /etc/modprobe.d/tipc.conf")
			}},

		// ── 3.3.x / 3.5.x MAC + Firewall ────────────────────────────────────
		//
		// These rules are cross-distro: MAC checks prefer SELinux when present
		// (RHEL/Rocky/AlmaLinux/Fedora/CentOS), falling back to AppArmor
		// (Ubuntu/Debian/SLES). Firewall checks accept any active backend.

		{ID: "3.3.1", Framework: cisBenchCIS, Level: 1, Section: cisCatMAC,
			Description: "Ensure a Mandatory Access Control framework is installed (AppArmor or SELinux)",
			Check: func(_ models.SecurityInfo, ks models.KernelSecurityInfo) models.CISResult {
				r := ruleByID("3.3.1")
				if ks.AppArmorPresent || ks.SELinuxPresent {
					return pass(r)
				}
				return failr(r, "no MAC framework detected",
					"install AppArmor or SELinux")
			}},

		{ID: "3.3.2", Framework: cisBenchCIS, Level: 1, Section: cisCatMAC,
			Description: "Ensure Mandatory Access Control is in enforce mode",
			Check: func(_ models.SecurityInfo, ks models.KernelSecurityInfo) models.CISResult {
				r := ruleByID("3.3.2")
				// SELinux path (RHEL/Rocky/AlmaLinux/Fedora — SELinux is the MAC)
				if ks.SELinuxPresent {
					switch ks.SELinuxMode {
					case "enforcing":
						return pass(r)
					case "permissive":
						return failr(r, "SELinux is in permissive mode — denials logged but not blocked",
							"set SELINUX=enforcing in /etc/selinux/config; setenforce 1")
					default:
						return failr(r, fmt.Sprintf("SELinux mode is %q (not enforcing)", ks.SELinuxMode),
							"set SELINUX=enforcing in /etc/selinux/config; reboot to activate")
					}
				}
				// AppArmor path (Ubuntu/Debian/SLES)
				if ks.AppArmorPresent {
					switch ks.AppArmorMode {
					case "enforce":
						return pass(r)
					case "complain":
						return failr(r, "AppArmor is in complain mode — denials logged but not blocked",
							"switch profiles to enforce mode: aa-enforce /etc/apparmor.d/*")
					case "unknown":
						return skipr(r, "AppArmor profile list unreadable (run as root)")
					default:
						return failr(r, "AppArmor is not in enforcing mode",
							"enable and enforce AppArmor: systemctl enable apparmor && aa-enforce /etc/apparmor.d/*")
					}
				}
				// No MAC framework installed at all
				return skipr(r, "no MAC framework installed — see 3.3.1")
			}},

		{ID: "3.5.1", Framework: cisBenchCIS, Level: 1, Section: cisCatNetwork,
			Description: "Ensure a firewall is installed and active",
			Check: func(sec models.SecurityInfo, _ models.KernelSecurityInfo) models.CISResult {
				r := ruleByID("3.5.1")
				if sec.FirewallUnreadable {
					return skipr(r, "firewall state unreadable (run as root for full inspection)")
				}
				if sec.FirewallActive {
					return pass(r)
				}
				if !sec.FirewallToolingPresent {
					return failr(r, "no firewall tooling detected",
						"install a firewall")
				}
				return failr(r, fmt.Sprintf("firewall tooling present (%s) but not active", sec.FirewallType),
					"enable the firewall: ufw enable (Ubuntu/Debian) or systemctl enable --now firewalld (RHEL/Rocky)")
			}},

		// ── 4.x Logging and Auditing ──────────────────────────────────────────

		{ID: cisRuleAudit41, StigID: "V-238360",
			StigDescription: "The Ubuntu operating system must have the auditd package installed", Framework: cisBenchBOTH, Level: 1, Section: "Audit",
			Description: "Ensure auditd is installed and running",
			Check: func(sec models.SecurityInfo, _ models.KernelSecurityInfo) models.CISResult {
				r := ruleByID(cisRuleAudit41)
				if sec.AuditRules == -1 {
					// remediation is rewritten per package manager in Evaluate
					return failr(r, "auditd not installed or not running",
						auditInstallCmd("apt"))
				}
				return pass(r)
			}},

		{ID: "4.1.2", StigID: "V-238361",
			StigDescription: "The auditd service must be running and enabled", Framework: cisBenchBOTH, Level: 1, Section: "Audit",
			Description: "Ensure auditd has rules configured",
			Check: func(sec models.SecurityInfo, _ models.KernelSecurityInfo) models.CISResult {
				r := ruleByID("4.1.2")
				if sec.AuditRules == -1 {
					return skipr(r, "auditd not available")
				}
				if sec.AuditRules == 0 {
					// remediation is rewritten per package manager in Evaluate
					return failr(r, "auditd running but no rules loaded",
						auditRulesCmd("apt"))
				}
				return pass(r)
			}},

		// ── 4.1.3-4.1.17 Audit event collection ──────────────────────────────────

		{ID: "4.1.3", Framework: cisBenchCIS, Level: 2, Section: "Audit",
			Description: "Ensure events that modify date and time information are collected",
			Check: func(_ models.SecurityInfo, _ models.KernelSecurityInfo) models.CISResult {
				return checkAuditRule(ruleByID("4.1.3"),
					[]string{"adjtimex", "clock_settime", "settimeofday"},
					"add '-a always,exit -F arch=b64 -S adjtimex,settimeofday,clock_settime -k time-change' to /etc/audit/rules.d/50-time-change.rules")
			}},

		{ID: "4.1.4", Framework: cisBenchCIS, Level: 2, Section: "Audit",
			Description: "Ensure events that modify user/group information are collected",
			Check: func(_ models.SecurityInfo, _ models.KernelSecurityInfo) models.CISResult {
				return checkAuditRule(ruleByID("4.1.4"),
					[]string{"-w /etc/passwd", "-w /etc/group", "-w /etc/shadow"},
					"add '-w /etc/passwd -p wa -k identity' to /etc/audit/rules.d/50-identity.rules")
			}},

		{ID: "4.1.5", Framework: cisBenchCIS, Level: 2, Section: "Audit",
			Description: "Ensure events that modify the network environment are collected",
			Check: func(_ models.SecurityInfo, _ models.KernelSecurityInfo) models.CISResult {
				return checkAuditRule(ruleByID("4.1.5"),
					[]string{"sethostname", "setdomainname", "-w /etc/hosts"},
					"add '-a always,exit -F arch=b64 -S sethostname,setdomainname -k system-locale' to /etc/audit/rules.d/50-system-locale.rules")
			}},

		{ID: "4.1.6", Framework: cisBenchCIS, Level: 2, Section: "Audit",
			Description: "Ensure events that modify the system's Mandatory Access Controls are collected",
			Check: func(_ models.SecurityInfo, _ models.KernelSecurityInfo) models.CISResult {
				return checkAuditRule(ruleByID("4.1.6"),
					[]string{"-w /etc/apparmor", "-w /etc/selinux"},
					"add '-w /etc/apparmor/ -p wa -k MAC-policy' to /etc/audit/rules.d/50-MAC-policy.rules")
			}},

		{ID: "4.1.7", Framework: cisBenchCIS, Level: 2, Section: "Audit",
			Description: "Ensure login and logout events are collected",
			Check: func(_ models.SecurityInfo, _ models.KernelSecurityInfo) models.CISResult {
				return checkAuditRule(ruleByID("4.1.7"),
					[]string{"-w /var/log/wtmp", "-w /var/log/faillog", "-w /var/log/btmp"},
					"add '-w /var/log/faillog -p wa -k logins' to /etc/audit/rules.d/50-login.rules")
			}},

		{ID: "4.1.8", Framework: cisBenchCIS, Level: 2, Section: "Audit",
			Description: "Ensure session initiation information is collected",
			Check: func(_ models.SecurityInfo, _ models.KernelSecurityInfo) models.CISResult {
				return checkAuditRule(ruleByID("4.1.8"),
					[]string{"-w /var/run/utmp", "-w /run/utmp"},
					"add '-w /var/run/utmp -p wa -k session' to /etc/audit/rules.d/50-session.rules")
			}},

		{ID: "4.1.9", Framework: cisBenchCIS, Level: 2, Section: "Audit",
			Description: "Ensure discretionary access control permission modification events are collected",
			Check: func(_ models.SecurityInfo, _ models.KernelSecurityInfo) models.CISResult {
				return checkAuditRule(ruleByID("4.1.9"),
					[]string{"chmod", "fchmod", "chown", "fchown"},
					"add '-a always,exit -F arch=b64 -S chmod,fchmod,chown,fchown,fchownat,fchmodat -k perm_mod' to /etc/audit/rules.d/50-perm-mod.rules")
			}},

		{ID: "4.1.10", Framework: cisBenchCIS, Level: 2, Section: "Audit",
			Description: "Ensure unsuccessful unauthorized file access attempts are collected",
			Check: func(_ models.SecurityInfo, _ models.KernelSecurityInfo) models.CISResult {
				return checkAuditRule(ruleByID("4.1.10"),
					[]string{"EACCES", "EPERM"},
					"add '-a always,exit -F arch=b64 -S creat,open,openat -F exit=-EACCES -k access' to /etc/audit/rules.d/50-access.rules")
			}},

		{ID: "4.1.11", Framework: cisBenchCIS, Level: 2, Section: "Audit",
			Description: "Ensure use of privileged commands is collected",
			Check: func(_ models.SecurityInfo, _ models.KernelSecurityInfo) models.CISResult {
				return checkAuditRule(ruleByID("4.1.11"),
					[]string{"-F perm=x -F auid>=", "-F path=/usr/bin/sudo"},
					"run: find / -xdev -perm -4000 -o -perm -2000 | awk '{print \"-a always,exit -F path=\"$1\" -F perm=x -F auid>=1000 -k privileged\"}' >> /etc/audit/rules.d/50-privileged.rules")
			}},

		{ID: "4.1.12", Framework: cisBenchCIS, Level: 2, Section: "Audit",
			Description: "Ensure successful file system mounts are collected",
			Check: func(_ models.SecurityInfo, _ models.KernelSecurityInfo) models.CISResult {
				return checkAuditRule(ruleByID("4.1.12"),
					[]string{"-S mount"},
					"add '-a always,exit -F arch=b64 -S mount -k mounts' to /etc/audit/rules.d/50-mounts.rules")
			}},

		{ID: "4.1.13", Framework: cisBenchCIS, Level: 2, Section: "Audit",
			Description: "Ensure use of file deletion events by users is collected",
			Check: func(_ models.SecurityInfo, _ models.KernelSecurityInfo) models.CISResult {
				return checkAuditRule(ruleByID("4.1.13"),
					[]string{"unlinkat", "rmdir", "unlink", "rename"},
					"add '-a always,exit -F arch=b64 -S unlinkat,rmdir,rename,renameat -k delete' to /etc/audit/rules.d/50-deletion.rules")
			}},

		{ID: "4.1.14", Framework: cisBenchCIS, Level: 2, Section: "Audit",
			Description: "Ensure changes to system administration scope (sudoers) are collected",
			Check: func(_ models.SecurityInfo, _ models.KernelSecurityInfo) models.CISResult {
				return checkAuditRule(ruleByID("4.1.14"),
					[]string{"-w /etc/sudoers"},
					"add '-w /etc/sudoers -p wa -k scope' to /etc/audit/rules.d/50-scope.rules")
			}},

		{ID: "4.1.15", Framework: cisBenchCIS, Level: 2, Section: "Audit",
			Description: "Ensure system administrator actions (sudolog) are collected",
			Check: func(_ models.SecurityInfo, _ models.KernelSecurityInfo) models.CISResult {
				return checkAuditRule(ruleByID("4.1.15"),
					[]string{"-w /var/log/sudo.log", "-w /var/log/auth.log"},
					"add '-w /var/log/sudo.log -p wa -k actions' to /etc/audit/rules.d/50-actions.rules")
			}},

		{ID: "4.1.16", Framework: cisBenchCIS, Level: 2, Section: "Audit",
			Description: "Ensure kernel module loading and unloading is collected",
			Check: func(_ models.SecurityInfo, _ models.KernelSecurityInfo) models.CISResult {
				return checkAuditRule(ruleByID("4.1.16"),
					[]string{"init_module", "finit_module", "delete_module"},
					"add '-a always,exit -F arch=b64 -S init_module,finit_module,delete_module -k modules' to /etc/audit/rules.d/50-modules.rules")
			}},

		{ID: "4.1.17", Framework: cisBenchCIS, Level: 2, Section: "Audit",
			Description: "Ensure the audit configuration is immutable",
			Check: func(_ models.SecurityInfo, _ models.KernelSecurityInfo) models.CISResult {
				return checkAuditRule(ruleByID("4.1.17"),
					[]string{"-e 2"},
					"add '-e 2' as the last line of /etc/audit/rules.d/99-finalize.rules")
			}},

		// ── 4.2 Rsyslog ──────────────────────────────────────────────────────

		{ID: "4.2.1", Framework: cisBenchCIS, Level: 1, Section: "Audit",
			Description: "Ensure rsyslog or syslog-ng is installed",
			Check: func(_ models.SecurityInfo, _ models.KernelSecurityInfo) models.CISResult {
				r := ruleByID("4.2.1")
				for _, p := range rsyslogBinPaths {
					if _, err := os.Stat(p); err == nil { //nolint:gosec // path is a package var, not user input
						return pass(r)
					}
				}
				return failr(r, "no syslog daemon found (rsyslogd or syslog-ng)",
					"install rsyslog (see remediation)")
			}},

		// ── 5.3/5.4 Auth ──────────────────────────────────────────────────────

		{ID: "5.3.1", Framework: cisBenchCIS, Level: 1, Section: cisCatAuth,
			Description: "Ensure sudo is installed",
			Check: func(_ models.SecurityInfo, _ models.KernelSecurityInfo) models.CISResult {
				r := ruleByID("5.3.1")
				for _, p := range sudoBinPaths {
					if _, err := os.Stat(p); err == nil {
						return pass(r)
					}
				}
				return failr(r,
					"sudo binary not found",
					"install sudo (see remediation)")
			}},

		{ID: "5.4.1", StigID: stigPassMaxDaysID, Framework: cisBenchBOTH, Level: 1, Section: cisCatAuth,
			Description: "Ensure password expiration is 365 days or less",
			Check: func(_ models.SecurityInfo, _ models.KernelSecurityInfo) models.CISResult {
				return checkLoginDefsField(ruleByID("5.4.1"), loginDefsPath, "PASS_MAX_DAYS",
					func(days int) bool { return days > 365 || days == 0 },
					"PASS_MAX_DAYS is %d", "set PASS_MAX_DAYS 365 in /etc/login.defs",
					"PASS_MAX_DAYS not set in /etc/login.defs", "add PASS_MAX_DAYS 365 to /etc/login.defs")
			}},

		{ID: "5.3.4", Framework: cisBenchCIS, Level: 1, Section: cisCatAuth,
			Description: "Ensure users must provide password for privilege escalation",
			Check: func(sec models.SecurityInfo, _ models.KernelSecurityInfo) models.CISResult {
				r := ruleByID("5.3.4")
				if sec.SudoersUnreadable {
					return skipr(r, "sudoers not readable — run as root for full coverage")
				}
				if len(sec.SudoNopasswd) == 0 {
					return pass(r)
				}
				return failr(r,
					fmt.Sprintf("NOPASSWD entries in sudoers: %s", strings.Join(sec.SudoNopasswd, ", ")),
					"remove NOPASSWD from /etc/sudoers and /etc/sudoers.d/")
			}},

		{ID: "5.3.2", Framework: cisBenchCIS, Level: 1, Section: cisCatAuth,
			Description: "Ensure sudo commands use a pseudo-terminal (Defaults use_pty)",
			Check: func(sec models.SecurityInfo, _ models.KernelSecurityInfo) models.CISResult {
				r := ruleByID("5.3.2")
				if sec.SudoersUnreadable {
					return skipr(r, "sudoers not readable — run as root for full coverage")
				}
				if !sec.SudoDefaultsPTY {
					return failr(r, "Defaults use_pty not set in sudoers",
						"add 'Defaults use_pty' to /etc/sudoers")
				}
				return pass(r)
			}},

		{ID: "5.3.3", Framework: cisBenchCIS, Level: 1, Section: cisCatAuth,
			Description: "Ensure sudo log file is configured (Defaults logfile=<path>)",
			Check: func(sec models.SecurityInfo, _ models.KernelSecurityInfo) models.CISResult {
				r := ruleByID("5.3.3")
				if sec.SudoersUnreadable {
					return skipr(r, "sudoers not readable — run as root for full coverage")
				}
				if !sec.SudoDefaultsLogfile {
					return failr(r, "Defaults logfile= not configured in sudoers",
						"add 'Defaults logfile=/var/log/sudo.log' to /etc/sudoers")
				}
				return pass(r)
			}},

		{ID: "5.4.2", Framework: cisBenchCIS, Level: 1, Section: cisCatAuth,
			Description: "Ensure all active user accounts have password expiry configured",
			Check: func(sec models.SecurityInfo, _ models.KernelSecurityInfo) models.CISResult {
				r := ruleByID("5.4.2")
				if sec.ShadowUnreadable {
					return skipr(r, "/etc/shadow not readable — run as root for full coverage")
				}
				if len(sec.StalePasswordAccounts) == 0 {
					return pass(r)
				}
				return failr(r,
					fmt.Sprintf("accounts without password expiry: %s", strings.Join(sec.StalePasswordAccounts, ", ")),
					"set expiry: chage --maxdays 365 <user>")
			}},

		{ID: "5.4.3", Framework: cisBenchCIS, Level: 1, Section: cisCatAuth,
			Description: "Ensure password hashing algorithm is SHA-512 or yescrypt",
			Check: func(_ models.SecurityInfo, _ models.KernelSecurityInfo) models.CISResult {
				r := ruleByID("5.4.3")
				data, err := os.ReadFile(loginDefsPath) //nolint:gosec // path is a package var, not user input
				if err != nil {
					return skipr(r, fmt.Sprintf("could not read %s", loginDefsPath))
				}
				for line := range strings.SplitSeq(string(data), "\n") {
					if strings.HasPrefix(strings.TrimSpace(line), "#") || strings.TrimSpace(line) == "" {
						continue
					}
					fields := strings.Fields(line)
					if len(fields) >= 2 && fields[0] == "ENCRYPT_METHOD" {
						method := strings.ToUpper(fields[1])
						if method == "SHA512" || method == "YESCRYPT" {
							return pass(r)
						}
						return failr(r,
							fmt.Sprintf("ENCRYPT_METHOD is %q (must be SHA512 or yescrypt)", fields[1]),
							"set ENCRYPT_METHOD SHA512 in /etc/login.defs")
					}
				}
				return failr(r,
					"ENCRYPT_METHOD not set in /etc/login.defs",
					"add ENCRYPT_METHOD SHA512 to /etc/login.defs")
			}},

		{ID: "5.4.4", Framework: cisBenchCIS, Level: 1, Section: cisCatAuth,
			Description: "Ensure minimum days between password changes is configured (PASS_MIN_DAYS ≥ 1)",
			Check: func(_ models.SecurityInfo, _ models.KernelSecurityInfo) models.CISResult {
				return checkLoginDefsField(ruleByID("5.4.4"), loginDefsPath, "PASS_MIN_DAYS",
					func(days int) bool { return days < 1 },
					"PASS_MIN_DAYS is %d (must be ≥ 1)", "set PASS_MIN_DAYS 1 in /etc/login.defs",
					"PASS_MIN_DAYS not set in /etc/login.defs", "add PASS_MIN_DAYS 1 to /etc/login.defs")
			}},

		{ID: "5.4.5", Framework: cisBenchCIS, Level: 1, Section: cisCatAuth,
			Description: "Ensure default group for root is GID 0",
			Check: func(_ models.SecurityInfo, _ models.KernelSecurityInfo) models.CISResult {
				r := ruleByID("5.4.5")
				data, err := os.ReadFile(useraddDefaultPath) //nolint:gosec // path is a package var, not user input
				if err != nil {
					return skipr(r, "/etc/default/useradd not readable")
				}
				for line := range strings.SplitSeq(string(data), "\n") {
					line = strings.TrimSpace(line)
					if strings.HasPrefix(line, "#") || line == "" {
						continue
					}
					if groupVal, matched := strings.CutPrefix(line, "GROUP="); matched {
						if groupVal == "0" || groupVal == "root" {
							return pass(r)
						}
						return failr(r,
							fmt.Sprintf("default GROUP is %q (must be 0 or root)", groupVal),
							"set GROUP=0 in /etc/default/useradd")
					}
				}
				return failr(r,
					"GROUP not set in /etc/default/useradd",
					"add GROUP=0 to /etc/default/useradd")
			}},

		{ID: "5.4.6", Framework: cisBenchCIS, Level: 1, Section: cisCatAuth,
			Description: "Ensure password expiration warning days is 7 or more (PASS_WARN_AGE ≥ 7)",
			Check: func(_ models.SecurityInfo, _ models.KernelSecurityInfo) models.CISResult {
				return checkLoginDefsField(ruleByID("5.4.6"), loginDefsPath, "PASS_WARN_AGE",
					func(days int) bool { return days < 7 },
					"PASS_WARN_AGE is %d (must be ≥ 7)", "set PASS_WARN_AGE 7 in /etc/login.defs",
					"PASS_WARN_AGE not set in /etc/login.defs", "add PASS_WARN_AGE 7 to /etc/login.defs")
			}},

		{ID: "5.4.7", Framework: cisBenchCIS, Level: 1, Section: cisCatAuth,
			Description: "Ensure inactive password lock is 30 days or less",
			Check: func(_ models.SecurityInfo, _ models.KernelSecurityInfo) models.CISResult {
				r := ruleByID("5.4.7")
				data, err := os.ReadFile(useraddDefaultPath) //nolint:gosec // package-level var
				if err != nil {
					return skipr(r, "/etc/default/useradd not readable")
				}
				for line := range strings.SplitSeq(string(data), "\n") {
					line = strings.TrimSpace(line)
					if strings.HasPrefix(line, "#") || line == "" {
						continue
					}
					if val, ok := strings.CutPrefix(line, "INACTIVE="); ok {
						n := 0
						if _, err := fmt.Sscanf(val, "%d", &n); err != nil {
							return skipr(r, fmt.Sprintf("cannot parse INACTIVE=%q", val))
						}
						if n < 0 {
							return failr(r, fmt.Sprintf("INACTIVE=%d — no automatic account lockout configured", n),
								"set INACTIVE=30 in /etc/default/useradd")
						}
						if n > 30 {
							return failr(r, fmt.Sprintf("INACTIVE=%d days (must be ≤ 30)", n),
								"set INACTIVE=30 in /etc/default/useradd")
						}
						return pass(r)
					}
				}
				return failr(r, "INACTIVE not set in /etc/default/useradd (no automatic lockout)",
					"set INACTIVE=30 in /etc/default/useradd")
			}},

		{ID: "5.4.8", Framework: cisBenchCIS, Level: 1, Section: cisCatAuth,
			Description: "Ensure system accounts do not have interactive shells",
			Check: func(_ models.SecurityInfo, _ models.KernelSecurityInfo) models.CISResult {
				r := ruleByID("5.4.8")
				data, err := os.ReadFile(etcPasswdPath) //nolint:gosec // package-level var
				if err != nil {
					return skipr(r, "could not read /etc/passwd")
				}
				const uidMin = 1000
				noInteractive := map[string]bool{
					"/sbin/nologin": true, "/usr/sbin/nologin": true,
					"/bin/false": true, "/usr/bin/false": true,
				}
				var bad []string
				for line := range strings.SplitSeq(string(data), "\n") {
					line = strings.TrimSpace(line)
					if line == "" || strings.HasPrefix(line, "#") {
						continue
					}
					fields := strings.SplitN(line, ":", 7)
					if len(fields) < 7 {
						continue
					}
					uid, err := strconv.Atoi(fields[2])
					if err != nil || uid == 0 || uid >= uidMin {
						continue
					}
					shell := strings.TrimSpace(fields[6])
					if !noInteractive[shell] {
						bad = append(bad, fmt.Sprintf("%s(uid=%d,shell=%s)", fields[0], uid, shell))
					}
				}
				if len(bad) > 0 {
					return failr(r,
						fmt.Sprintf("system accounts with interactive shells: %s", strings.Join(bad, " ")),
						"set shell: usermod -s /usr/sbin/nologin <user>")
				}
				return pass(r)
			}},

		{ID: "5.3.5", Framework: cisBenchCIS, Level: 1, Section: cisCatAuth,
			Description: "Ensure sudo authentication timeout is 15 minutes or less",
			Check: func(sec models.SecurityInfo, _ models.KernelSecurityInfo) models.CISResult {
				r := ruleByID("5.3.5")
				if sec.SudoersUnreadable {
					return skipr(r, "sudoers not readable — run as root for full coverage")
				}
				if sec.SudoTimestampNever {
					return failr(r, "Defaults timestamp_timeout < 0 — sudo sessions never expire",
						"add 'Defaults timestamp_timeout=15' to /etc/sudoers")
				}
				if sec.SudoTimestampMins > 15 {
					return failr(r,
						fmt.Sprintf("Defaults timestamp_timeout=%d minutes exceeds CIS 15-minute limit", sec.SudoTimestampMins),
						"set 'Defaults timestamp_timeout=15' in /etc/sudoers")
				}
				return pass(r)
			}},

		// ── 5.1 Cron Daemon Configuration ────────────────────────────────────

		{ID: "5.1.2", Framework: cisBenchCIS, Level: 1, Section: "Cron",
			Description: "Ensure permissions on /etc/crontab are configured (0600)",
			Check: func(_ models.SecurityInfo, _ models.KernelSecurityInfo) models.CISResult {
				r := ruleByID("5.1.2")
				return checkFilePerm(r, "/etc/crontab", 0o600, "chown root:root /etc/crontab && chmod og-rwx /etc/crontab")
			}},

		{ID: "5.1.3", Framework: cisBenchCIS, Level: 1, Section: "Cron",
			Description: "Ensure permissions on /etc/cron.hourly are configured (0700)",
			Check: func(_ models.SecurityInfo, _ models.KernelSecurityInfo) models.CISResult {
				r := ruleByID("5.1.3")
				return checkFilePerm(r, "/etc/cron.hourly", 0o700, "chmod og-rwx /etc/cron.hourly")
			}},

		{ID: "5.1.4", Framework: cisBenchCIS, Level: 1, Section: "Cron",
			Description: "Ensure permissions on /etc/cron.daily are configured (0700)",
			Check: func(_ models.SecurityInfo, _ models.KernelSecurityInfo) models.CISResult {
				r := ruleByID("5.1.4")
				return checkFilePerm(r, "/etc/cron.daily", 0o700, "chmod og-rwx /etc/cron.daily")
			}},

		{ID: "5.1.5", Framework: cisBenchCIS, Level: 1, Section: "Cron",
			Description: "Ensure permissions on /etc/cron.weekly are configured (0700)",
			Check: func(_ models.SecurityInfo, _ models.KernelSecurityInfo) models.CISResult {
				r := ruleByID("5.1.5")
				return checkFilePerm(r, "/etc/cron.weekly", 0o700, "chmod og-rwx /etc/cron.weekly")
			}},

		{ID: "5.1.6", Framework: cisBenchCIS, Level: 1, Section: "Cron",
			Description: "Ensure permissions on /etc/cron.monthly are configured (0700)",
			Check: func(_ models.SecurityInfo, _ models.KernelSecurityInfo) models.CISResult {
				r := ruleByID("5.1.6")
				return checkFilePerm(r, "/etc/cron.monthly", 0o700, "chmod og-rwx /etc/cron.monthly")
			}},

		{ID: "5.1.7", Framework: cisBenchCIS, Level: 1, Section: "Cron",
			Description: "Ensure permissions on /etc/cron.d are configured (0700)",
			Check: func(_ models.SecurityInfo, _ models.KernelSecurityInfo) models.CISResult {
				r := ruleByID("5.1.7")
				return checkFilePerm(r, "/etc/cron.d", 0o700, "chmod og-rwx /etc/cron.d")
			}},

		{ID: "5.1.8", Framework: cisBenchCIS, Level: 1, Section: "Cron",
			Description: "Ensure cron is restricted to authorized users (/etc/cron.allow or /etc/cron.deny)",
			Check: func(_ models.SecurityInfo, _ models.KernelSecurityInfo) models.CISResult {
				r := ruleByID("5.1.8")
				if _, err := os.Stat(cronAllowPath); err == nil {
					return pass(r)
				}
				if _, err := os.Stat(cronDenyPath); err == nil {
					return pass(r)
				}
				return failr(r, "neither /etc/cron.allow nor /etc/cron.deny exists",
					"create /etc/cron.allow with authorized users (one per line)")
			}},

		{ID: "5.1.9", Framework: cisBenchCIS, Level: 1, Section: "Cron",
			Description: "Ensure at is restricted to authorized users (/etc/at.allow or /etc/at.deny)",
			Check: func(_ models.SecurityInfo, _ models.KernelSecurityInfo) models.CISResult {
				r := ruleByID("5.1.9")
				if _, err := os.Stat(atAllowPath); err == nil {
					return pass(r)
				}
				if _, err := os.Stat(atDenyPath); err == nil {
					return pass(r)
				}
				return failr(r, "neither /etc/at.allow nor /etc/at.deny exists",
					"create /etc/at.allow with authorized users (one per line)")
			}},

		// ── 1.1 Filesystem ────────────────────────────────────────────────────

		{ID: "1.1.22", Framework: cisBenchCIS, Level: 1, Section: "Filesystem",
			Description: "Ensure sticky bit is set on all world-writable directories",
			Check: func(sec models.SecurityInfo, _ models.KernelSecurityInfo) models.CISResult {
				r := ruleByID("1.1.22")
				if len(sec.WorldWritableDirs) == 0 {
					return pass(r)
				}
				return failr(r,
					fmt.Sprintf("world-writable dirs missing sticky bit: %s", strings.Join(sec.WorldWritableDirs, ", ")),
					"set sticky bit: chmod +t /tmp /var/tmp /dev/shm")
			}},

		// ── 6.x System Maintenance ────────────────────────────────────────────

		{ID: "6.1.1", StigID: "V-238401", Framework: cisBenchBOTH, Level: 1, Section: cisCatFiles,
			Description: "Ensure /etc/passwd permissions are 644 or stricter",
			Check: func(_ models.SecurityInfo, _ models.KernelSecurityInfo) models.CISResult {
				r := ruleByID("6.1.1")
				return checkFilePerm(r, etcPasswdPath, 0o644, "chmod 644 /etc/passwd")
			}},

		{ID: "6.1.2", StigID: "V-238402", Framework: cisBenchBOTH, Level: 1, Section: cisCatFiles,
			Description: "Ensure /etc/shadow permissions are 000 or 640",
			Check: func(_ models.SecurityInfo, _ models.KernelSecurityInfo) models.CISResult {
				r := ruleByID("6.1.2")
				return checkFilePerm(r, etcShadowPath, 0o640, "chmod 000 /etc/shadow")
			}},

		{ID: "6.1.3", StigID: "V-238403", Framework: cisBenchBOTH, Level: 1, Section: cisCatFiles,
			Description: "Ensure /etc/group permissions are 644 or stricter",
			Check: func(_ models.SecurityInfo, _ models.KernelSecurityInfo) models.CISResult {
				r := ruleByID("6.1.3")
				return checkFilePerm(r, etcGroupPath, 0o644, "chmod 644 /etc/group")
			}},

		{ID: "6.1.4", Framework: cisBenchCIS, Level: 1, Section: cisCatFiles,
			Description: "Ensure /etc/passwd- permissions are 600 or stricter",
			Check: func(_ models.SecurityInfo, _ models.KernelSecurityInfo) models.CISResult {
				r := ruleByID("6.1.4")
				return checkFilePerm(r, "/etc/passwd-", 0o600, "chmod 600 /etc/passwd-")
			}},

		{ID: "6.1.5", Framework: cisBenchCIS, Level: 1, Section: cisCatFiles,
			Description: "Ensure /etc/shadow- permissions are 000 or 600",
			Check: func(_ models.SecurityInfo, _ models.KernelSecurityInfo) models.CISResult {
				r := ruleByID("6.1.5")
				return checkFilePerm(r, "/etc/shadow-", 0o600, "chmod 000 /etc/shadow-")
			}},

		{ID: "6.1.6", Framework: cisBenchCIS, Level: 1, Section: cisCatFiles,
			Description: "Ensure /etc/gshadow permissions are 000 or 640",
			Check: func(_ models.SecurityInfo, _ models.KernelSecurityInfo) models.CISResult {
				r := ruleByID("6.1.6")
				return checkFilePerm(r, "/etc/gshadow", 0o640, "chmod 000 /etc/gshadow")
			}},

		{ID: "6.1.7", Framework: cisBenchCIS, Level: 1, Section: cisCatFiles,
			Description: "Ensure /etc/gshadow- permissions are 000 or 600",
			Check: func(_ models.SecurityInfo, _ models.KernelSecurityInfo) models.CISResult {
				r := ruleByID("6.1.7")
				return checkFilePerm(r, "/etc/gshadow-", 0o600, "chmod 000 /etc/gshadow-")
			}},

		{ID: "6.1.8", Framework: cisBenchCIS, Level: 1, Section: cisCatFiles,
			Description: "Ensure /etc/group- permissions are 644 or stricter",
			Check: func(_ models.SecurityInfo, _ models.KernelSecurityInfo) models.CISResult {
				r := ruleByID("6.1.8")
				return checkFilePerm(r, "/etc/group-", 0o644, "chmod 644 /etc/group-")
			}},

		// ── 6.1.9–6.1.13 File Ownership ──────────────────────────────────────

		{ID: "6.1.9", Framework: cisBenchCIS, Level: 1, Section: cisCatFiles,
			Description: "Ensure /etc/passwd is owned by root:root",
			Check: func(_ models.SecurityInfo, _ models.KernelSecurityInfo) models.CISResult {
				return checkFileOwnerRootRoot(ruleByID("6.1.9"), etcPasswdPath, "chown root:root /etc/passwd")
			}},

		{ID: "6.1.10", Framework: cisBenchCIS, Level: 1, Section: cisCatFiles,
			Description: "Ensure /etc/shadow is owned by root:root or root:shadow",
			Check: func(_ models.SecurityInfo, _ models.KernelSecurityInfo) models.CISResult {
				return checkFileOwnerRootRootOrShadow(ruleByID("6.1.10"), etcShadowPath, "chown root:shadow /etc/shadow")
			}},

		{ID: "6.1.11", Framework: cisBenchCIS, Level: 1, Section: cisCatFiles,
			Description: "Ensure /etc/group is owned by root:root",
			Check: func(_ models.SecurityInfo, _ models.KernelSecurityInfo) models.CISResult {
				return checkFileOwnerRootRoot(ruleByID("6.1.11"), etcGroupPath, "chown root:root /etc/group")
			}},

		{ID: "6.1.12", Framework: cisBenchCIS, Level: 1, Section: cisCatFiles,
			Description: "Ensure /etc/passwd- is owned by root:root",
			Check: func(_ models.SecurityInfo, _ models.KernelSecurityInfo) models.CISResult {
				return checkFileOwnerRootRoot(ruleByID("6.1.12"), "/etc/passwd-", "chown root:root /etc/passwd-")
			}},

		{ID: "6.1.13", Framework: cisBenchCIS, Level: 1, Section: cisCatFiles,
			Description: "Ensure /etc/shadow- is owned by root:root or root:shadow",
			Check: func(_ models.SecurityInfo, _ models.KernelSecurityInfo) models.CISResult {
				return checkFileOwnerRootRootOrShadow(ruleByID("6.1.13"), "/etc/shadow-", "chown root:shadow /etc/shadow-")
			}},

		{ID: "6.2.1", StigID: "V-238408", Framework: cisBenchBOTH, Level: 1, Section: "Users",
			Description: "Ensure no accounts have empty password fields",
			Check: func(sec models.SecurityInfo, _ models.KernelSecurityInfo) models.CISResult {
				r := ruleByID("6.2.1")
				if sec.ShadowUnreadable {
					return skipr(r, "/etc/shadow not readable (run as root) — empty-password state not verified")
				}
				if len(sec.EmptyPasswordAccounts) > 0 {
					return failr(r,
						fmt.Sprintf("accounts with empty password: %s", strings.Join(sec.EmptyPasswordAccounts, ", ")),
						"lock each account: passwd -l <user>")
				}
				return pass(r)
			}},

		{ID: "6.2.2", StigID: "V-238410", Framework: cisBenchBOTH, Level: 1, Section: "Users",
			Description: "Ensure no legacy '+' entries in /etc/passwd, /etc/shadow, /etc/group",
			Check: func(_ models.SecurityInfo, _ models.KernelSecurityInfo) models.CISResult {
				r := ruleByID("6.2.2")
				for _, path := range legacyNISPaths {
					data, err := os.ReadFile(path) // #nosec G304
					if err != nil {
						continue
					}
					for line := range strings.SplitSeq(string(data), "\n") {
						if strings.HasPrefix(strings.TrimSpace(line), "+") {
							return failr(r, fmt.Sprintf("legacy NIS '+' entry in %s", path),
								fmt.Sprintf("remove the '+' line from %s", path))
						}
					}
				}
				return pass(r)
			}},

		{ID: "6.2.3", StigID: "V-238411", Framework: cisBenchBOTH, Level: 1, Section: "Users",
			Description: "Ensure root is the only UID 0 account",
			Check: func(sec models.SecurityInfo, _ models.KernelSecurityInfo) models.CISResult {
				r := ruleByID("6.2.3")
				if len(sec.UID0Users) > 0 {
					return failr(r, fmt.Sprintf("UID 0 accounts: %s", strings.Join(sec.UID0Users, ", ")),
						"lock or remove these accounts: passwd -l <user>")
				}
				return pass(r)
			}},

		{ID: "6.1.14", Framework: cisBenchCIS, Level: 1, Section: cisCatFiles,
			Description: "Audit SUID executables — ensure no unexpected SUID binaries exist",
			Check: func(sec models.SecurityInfo, _ models.KernelSecurityInfo) models.CISResult {
				r := ruleByID("6.1.14")
				if len(sec.SUIDBinaries) == 0 {
					return pass(r)
				}
				return failr(r,
					fmt.Sprintf("unexpected SUID binaries: %s", strings.Join(sec.SUIDBinaries, ", ")),
					"review each binary; remove SUID if not needed: chmod u-s <path>")
			}},

		{ID: "6.2.4", Framework: cisBenchCIS, Level: 1, Section: "Users",
			Description: "Ensure no accounts have empty passwords",
			Check: func(sec models.SecurityInfo, _ models.KernelSecurityInfo) models.CISResult {
				r := ruleByID("6.2.4")
				if sec.ShadowUnreadable {
					return skipr(r, "/etc/shadow not readable — run as root for full coverage")
				}
				if len(sec.EmptyPasswordAccounts) == 0 {
					return pass(r)
				}
				return failr(r,
					fmt.Sprintf("accounts with empty passwords: %s", strings.Join(sec.EmptyPasswordAccounts, ", ")),
					"set passwords or lock accounts: passwd -l <user>")
			}},

		{ID: "6.2.5", Framework: cisBenchCIS, Level: 1, Section: "Users",
			Description: "Ensure no duplicate UIDs exist",
			Check: func(_ models.SecurityInfo, _ models.KernelSecurityInfo) models.CISResult {
				r := ruleByID("6.2.5")
				data, err := os.ReadFile(etcPasswdPath)
				if err != nil {
					return skipr(r, "could not read /etc/passwd")
				}
				seen := map[string]bool{}
				var dups []string
				for line := range strings.SplitSeq(string(data), "\n") {
					line = strings.TrimSpace(line)
					if line == "" || strings.HasPrefix(line, "#") {
						continue
					}
					fields := strings.SplitN(line, ":", 4)
					if len(fields) < 3 {
						continue
					}
					uid := fields[2]
					if seen[uid] {
						dups = append(dups, uid)
					}
					seen[uid] = true
				}
				if len(dups) > 0 {
					return failr(r, fmt.Sprintf("duplicate UIDs in /etc/passwd: %s", strings.Join(dups, ", ")),
						"remove or reassign duplicate UID accounts")
				}
				return pass(r)
			}},

		{ID: "6.2.6", Framework: cisBenchCIS, Level: 1, Section: "Users",
			Description: "Ensure no duplicate GIDs exist",
			Check: func(_ models.SecurityInfo, _ models.KernelSecurityInfo) models.CISResult {
				r := ruleByID("6.2.6")
				data, err := os.ReadFile(etcGroupPath)
				if err != nil {
					return skipr(r, "could not read /etc/group")
				}
				seen := map[string]bool{}
				var dups []string
				for line := range strings.SplitSeq(string(data), "\n") {
					line = strings.TrimSpace(line)
					if line == "" || strings.HasPrefix(line, "#") {
						continue
					}
					fields := strings.SplitN(line, ":", 4)
					if len(fields) < 3 {
						continue
					}
					gid := fields[2]
					if seen[gid] {
						dups = append(dups, gid)
					}
					seen[gid] = true
				}
				if len(dups) > 0 {
					return failr(r, fmt.Sprintf("duplicate GIDs in /etc/group: %s", strings.Join(dups, ", ")),
						"remove or reassign duplicate GID groups")
				}
				return pass(r)
			}},

		{ID: "6.2.7", Framework: cisBenchCIS, Level: 1, Section: "Users",
			Description: "Ensure no duplicate user names exist",
			Check: func(_ models.SecurityInfo, _ models.KernelSecurityInfo) models.CISResult {
				r := ruleByID("6.2.7")
				data, err := os.ReadFile(etcPasswdPath)
				if err != nil {
					return skipr(r, "could not read /etc/passwd")
				}
				seen := map[string]bool{}
				var dups []string
				for line := range strings.SplitSeq(string(data), "\n") {
					line = strings.TrimSpace(line)
					if line == "" || strings.HasPrefix(line, "#") {
						continue
					}
					fields := strings.SplitN(line, ":", 2)
					if len(fields) < 1 {
						continue
					}
					username := fields[0]
					if seen[username] {
						dups = append(dups, username)
					}
					seen[username] = true
				}
				if len(dups) > 0 {
					return failr(r, fmt.Sprintf("duplicate usernames in /etc/passwd: %s", strings.Join(dups, ", ")),
						"remove or rename duplicate user accounts")
				}
				return pass(r)
			}},

		{ID: "6.2.8", Framework: cisBenchCIS, Level: 1, Section: "Users",
			Description: "Ensure no duplicate group names exist",
			Check: func(_ models.SecurityInfo, _ models.KernelSecurityInfo) models.CISResult {
				r := ruleByID("6.2.8")
				data, err := os.ReadFile(etcGroupPath)
				if err != nil {
					return skipr(r, "could not read /etc/group")
				}
				seen := map[string]bool{}
				var dups []string
				for line := range strings.SplitSeq(string(data), "\n") {
					line = strings.TrimSpace(line)
					if line == "" || strings.HasPrefix(line, "#") {
						continue
					}
					fields := strings.SplitN(line, ":", 2)
					if len(fields) < 1 {
						continue
					}
					groupname := fields[0]
					if seen[groupname] {
						dups = append(dups, groupname)
					}
					seen[groupname] = true
				}
				if len(dups) > 0 {
					return failr(r, fmt.Sprintf("duplicate group names in /etc/group: %s", strings.Join(dups, ", ")),
						"remove or rename duplicate groups")
				}
				return pass(r)
			}},

		{ID: "6.2.9", Framework: cisBenchCIS, Level: 1, Section: "Users",
			Description: "Ensure root is the only UID 0 account",
			Check: func(_ models.SecurityInfo, _ models.KernelSecurityInfo) models.CISResult {
				r := ruleByID("6.2.9")
				data, err := os.ReadFile(etcPasswdPath)
				if err != nil {
					return skipr(r, "could not read /etc/passwd")
				}
				var nonRoot []string
				for line := range strings.SplitSeq(string(data), "\n") {
					line = strings.TrimSpace(line)
					if line == "" || strings.HasPrefix(line, "#") {
						continue
					}
					fields := strings.SplitN(line, ":", 4)
					if len(fields) < 3 {
						continue
					}
					if fields[2] == "0" && fields[0] != "root" {
						nonRoot = append(nonRoot, fields[0])
					}
				}
				if len(nonRoot) > 0 {
					return failr(r,
						fmt.Sprintf("non-root accounts with UID 0: %s", strings.Join(nonRoot, ", ")),
						"remove or reassign UID for non-root accounts with uid=0")
				}
				return pass(r)
			}},

		// ── STIG-only rules (no direct CIS equivalent) ────────────────────────

		// V-238213: Approved ciphers — STIG mandates only FIPS-approved ciphers
		{ID: "V-238213", Framework: cisBenchSTIG, Level: 1, Section: cisCatSSH,
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
		{ID: "V-238214", Framework: cisBenchSTIG, Level: 1, Section: cisCatSSH,
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
		{ID: "V-238215", Framework: cisBenchSTIG, Level: 1, Section: cisCatSSH,
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
		{ID: "V-238221", Framework: cisBenchSTIG, Level: 1, Section: cisCatSSH,
			Description: "The SSH daemon must set ClientAliveCountMax to 0",
			Check: func(sec models.SecurityInfo, _ models.KernelSecurityInfo) models.CISResult {
				r := ruleByID("V-238221")
				// We don't currently parse ClientAliveCountMax — treat as manual
				return models.CISResult{
					ID: r.ID, Framework: cisBenchSTIG, Level: r.Level, Section: r.Section,
					Description: r.Description, Status: models.CISManual,
					Finding: "run: grep -i ClientAliveCountMax /etc/ssh/sshd_config — value must be 0",
				}
			}},

		// V-238226: SSH StrictModes
		{ID: "V-238226", Framework: cisBenchSTIG, Level: 1, Section: cisCatSSH,
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
		{ID: stigPassMaxDaysID, Framework: cisBenchSTIG, Level: 1, Section: cisCatAuth,
			Description: "The Ubuntu OS must enforce a 60-day maximum password age",
			Check: func(_ models.SecurityInfo, _ models.KernelSecurityInfo) models.CISResult {
				return checkLoginDefsField(ruleByID(stigPassMaxDaysID), loginDefsPath, "PASS_MAX_DAYS",
					func(days int) bool { return days > 60 || days == 0 },
					"PASS_MAX_DAYS is %d (STIG requires ≤ 60)", "set PASS_MAX_DAYS 60 in /etc/login.defs",
					"PASS_MAX_DAYS not set", "add PASS_MAX_DAYS 60 to /etc/login.defs")
			}},

		// V-238382: Minimum password age (STIG-specific)
		{ID: "V-238382", Framework: cisBenchSTIG, Level: 1, Section: cisCatAuth,
			Description: "The Ubuntu OS must enforce a minimum 1-day password age",
			Check: func(_ models.SecurityInfo, _ models.KernelSecurityInfo) models.CISResult {
				return checkLoginDefsField(ruleByID("V-238382"), loginDefsPath, "PASS_MIN_DAYS",
					func(days int) bool { return days < 1 },
					"PASS_MIN_DAYS is %d (must be ≥ 1)", "set PASS_MIN_DAYS 1 in /etc/login.defs",
					"PASS_MIN_DAYS not set in /etc/login.defs", "add PASS_MIN_DAYS 1 to /etc/login.defs")
			}},

		// V-238383: Password warning age (STIG-specific)
		{ID: "V-238383", Framework: cisBenchSTIG, Level: 1, Section: cisCatAuth,
			Description: "The Ubuntu OS must warn users 7 days before password expiry",
			Check: func(_ models.SecurityInfo, _ models.KernelSecurityInfo) models.CISResult {
				return checkLoginDefsField(ruleByID("V-238383"), loginDefsPath, "PASS_WARN_AGE",
					func(days int) bool { return days < 7 },
					"PASS_WARN_AGE is %d (must be ≥ 7)", "set PASS_WARN_AGE 7 in /etc/login.defs",
					"PASS_WARN_AGE not set in /etc/login.defs", "add PASS_WARN_AGE 7 to /etc/login.defs")
			}},
	}
}

// loginDefsPath is the /etc/login.defs location consulted by the password-aging
// rules (5.4.1, V-238380, V-238382, V-238383). It is a package-level var — not a
// const — so tests can point it at a t.TempDir() fixture instead of the real host
// file, per the project rule against reading live host paths in tests.
var loginDefsPath = "/etc/login.defs"

// sshdConfigPath is the sshd_config location checked by rule 5.2.1 for its file
// mode. Package-level var so tests can point it at a t.TempDir() fixture.
var sshdConfigPath = "/etc/ssh/sshd_config"

// legacyNISPaths is the list of files scanned by rule 6.2.2 for legacy '+' NIS
// entries. Package-level var so tests can supply in-memory fixture paths.
var legacyNISPaths = []string{etcPasswdPath, etcShadowPath, etcGroupPath}

// chronyCfgPaths is the ordered list of chrony config file locations checked by
// rules 2.1.1 and 2.1.2. RHEL/Rocky put the file at /etc/chrony.conf;
// Debian/Ubuntu put it at /etc/chrony/chrony.conf. Package-level var for test injection.
var chronyCfgPaths = []string{"/etc/chrony.conf", "/etc/chrony/chrony.conf"}

// ntpCfgPath and timesyncdCfgPath are the config file locations for ntpd and
// systemd-timesyncd respectively. Package-level vars for test injection.
var ntpCfgPath = "/etc/ntp.conf"
var timesyncdCfgPath = "/etc/systemd/timesyncd.conf"

// sudoBinPaths is the ordered list of paths where the sudo binary may live.
// Package-level var so tests can inject a t.TempDir() fixture instead of the
// real host path.
var sudoBinPaths = []string{"/usr/bin/sudo", "/bin/sudo"}

// useraddDefaultPath is the useradd defaults file checked by rule 5.4.5.
// Package-level var for test injection.
var useraddDefaultPath = "/etc/default/useradd"

// motdPath, issuePath, issueNetPath are the banner files checked by rules
// 1.7.1–1.7.6. Package-level vars so tests can inject t.TempDir() fixtures.
var motdPath = "/etc/motd"
var issuePath = "/etc/issue"
var issueNetPath = "/etc/issue.net"

// nisBinPaths, rshBinPaths, talkBinPaths, telnetBinPaths are the binary paths
// checked by the "legacy service not installed" rules (2.2.x). If any path
// exists on the host, the service is considered installed → FAIL.
var nisBinPaths = []string{"/usr/sbin/ypbind", "/usr/bin/ypcat", "/usr/bin/ypmatch"}
var rshBinPaths = []string{"/usr/bin/rsh", "/usr/bin/rlogin", "/usr/bin/rcp"}
var talkBinPaths = []string{"/usr/bin/talk", "/usr/bin/ntalk"}
var telnetBinPaths = []string{"/usr/bin/telnet", "/usr/lib/telnet/telnet"}

// xorgBinPaths, avahiBinPaths, cupsBinPaths, dhcpBinPaths, slapdBinPaths are
// checked by the "server daemon not installed" rules (2.3.x).
var xorgBinPaths = []string{"/usr/bin/Xorg", "/usr/bin/X", "/usr/lib/xorg/Xorg"}
var avahiBinPaths = []string{"/usr/sbin/avahi-daemon"}
var cupsBinPaths = []string{"/usr/sbin/cupsd"}
var dhcpBinPaths = []string{"/usr/sbin/dhcpd"}
var slapdBinPaths = []string{"/usr/sbin/slapd"}

// grubCfgPaths is the ordered list of GRUB config file locations checked by
// rules 1.4.1 and 1.4.2. Ubuntu/Debian use /boot/grub/grub.cfg; RHEL/Rocky
// use /boot/grub2/grub.cfg. Package-level var for test injection.
var grubCfgPaths = []string{"/boot/grub/grub.cfg", "/boot/grub2/grub.cfg"}

// cronAllowPath, cronDenyPath, atAllowPath, atDenyPath are the access-control
// files checked by rules 5.1.8 and 5.1.9. Package-level vars for test injection.
var cronAllowPath = "/etc/cron.allow"
var cronDenyPath = "/etc/cron.deny"
var atAllowPath = "/etc/at.allow"
var atDenyPath = "/etc/at.deny"

// rsyslogBinPaths is the set of syslog daemon binaries checked by rule 4.2.1.
// Both rsyslog and syslog-ng satisfy the "logging daemon installed" requirement.
var rsyslogBinPaths = []string{"/usr/sbin/rsyslogd", "/sbin/rsyslogd", "/usr/sbin/syslog-ng"}

// procModulesPath is /proc/modules — checked by kernel-module disabled rules (1.1.1.x, 3.4.x).
// Package-level var for test injection.
var procModulesPath = "/proc/modules"

// modprobeDPath is the modprobe.d config directory scanned by checkModuleDisabled.
var modprobeDPath = "/etc/modprobe.d"

// procMountsPath is /proc/mounts — checked by filesystem mount-option rules (1.1.x).
var procMountsPath = "/proc/mounts"

// etcPasswdPath, etcShadowPath, and etcGroupPath are the user/group databases
// and shadow file, referenced by permission/ownership rules (6.1.x), legacy NIS
// scan (6.2.2), and account-audit rules (5.4.8, 6.2.5–6.2.8).
var etcPasswdPath = "/etc/passwd"
var etcShadowPath = "/etc/shadow"
var etcGroupPath = "/etc/group"

// prelinkBinPaths for rule 1.5.2 (prelink not installed).
var prelinkBinPaths = []string{"/usr/sbin/prelink"}

// Service daemons that must not be installed (2.3.6-2.3.13).
var nfsBinPaths = []string{"/usr/sbin/nfsd", "/usr/sbin/rpc.nfsd"}
var namedBinPaths = []string{"/usr/sbin/named", "/usr/bin/named"}
var ftpBinPaths = []string{"/usr/sbin/vsftpd", "/usr/sbin/proftpd", "/usr/sbin/pure-ftpd"}
var httpBinPaths = []string{"/usr/sbin/apache2", "/usr/sbin/httpd", "/usr/sbin/nginx"}
var imapBinPaths = []string{"/usr/sbin/dovecot"}
var sambaBinPaths = []string{"/usr/sbin/smbd"}
var squidBinPaths = []string{"/usr/sbin/squid", "/usr/sbin/squid3"}
var snmpBinPaths = []string{"/usr/sbin/snmpd"}

// auditRulesDPath and auditRulesFilePath for audit rule checks (4.1.3–4.1.17).
var auditRulesDPath    = "/etc/audit/rules.d"
var auditRulesFilePath = "/etc/audit/audit.rules"

// checkLoginDefsField reads path (normally /etc/login.defs) for the first
// uncommented "field value..." line and applies fails(days) to decide PASS/FAIL.
// notSetFinding/notSetFix are used when the field is entirely absent from the
// file. All four password-aging rules (CIS 5.4.1 and STIG V-238380/382/383)
// share this exact read/scan/parse shape and differ only in the field name and
// threshold predicate.
func checkLoginDefsField(r Rule, path, field string, fails func(days int) bool, // NOSONAR — CIS rule helper; each param is a distinct configurable aspect of the check
	failFmt, failFix, notSetFinding, notSetFix string,
) models.CISResult {
	data, err := os.ReadFile(path) // #nosec G304 -- hardcoded/injected login.defs path
	if err != nil {
		return skipr(r, fmt.Sprintf("could not read %s", path))
	}
	for line := range strings.SplitSeq(string(data), "\n") {
		if strings.HasPrefix(strings.TrimSpace(line), "#") {
			continue
		}
		if strings.HasPrefix(line, field) {
			fields := strings.Fields(line)
			if len(fields) >= 2 {
				days := 0
				fmt.Sscanf(fields[1], "%d", &days) //nolint:errcheck
				if fails(days) {
					return failr(r, fmt.Sprintf(failFmt, days), failFix)
				}
			}
			return pass(r)
		}
	}
	return failr(r, notSetFinding, notSetFix)
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

// checkBannerContent verifies path holds a non-empty warning banner without
// agetty OS-fingerprinting escape sequences (\s, \m, \r, \v, \u). A missing
// or empty file means no warning is shown to users at login.
func checkBannerContent(r Rule, path, fix string) models.CISResult {
	data, err := os.ReadFile(path) //nolint:gosec // path is a package var, not user input
	if err != nil {
		return failr(r, fmt.Sprintf("%s not found — no login banner configured", path), fix)
	}
	if strings.TrimSpace(string(data)) == "" {
		return failr(r, fmt.Sprintf("%s is empty — configure a login warning banner", path), fix)
	}
	for _, seq := range []string{`\s`, `\m`, `\r`, `\v`, `\u`} {
		if strings.Contains(string(data), seq) {
			return failr(r, fmt.Sprintf("%s contains OS fingerprinting sequence %q", path, seq),
				"remove \\s \\m \\r \\v \\u sequences from "+path)
		}
	}
	return pass(r)
}

// checkFileOwnerRootRoot fails when path is not owned by uid=0, gid=0 (root:root).
func checkFileOwnerRootRoot(r Rule, path, fix string) models.CISResult {
	fi, err := os.Stat(path) //nolint:gosec // path is a hardcoded system path
	if err != nil {
		return skipr(r, fmt.Sprintf("%s not found", path))
	}
	stat, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		return skipr(r, fmt.Sprintf("cannot determine ownership of %s", path))
	}
	if stat.Uid != 0 || stat.Gid != 0 {
		return failr(r, fmt.Sprintf("%s owned by uid=%d gid=%d (must be root:root)", path, stat.Uid, stat.Gid), fix)
	}
	return pass(r)
}

// checkFileOwnerRootRootOrShadow fails when path is not owned by uid=0 with
// gid=0 (root:root) or gid matching the "shadow" group. Used for /etc/shadow
// and /etc/shadow- which are typically owned root:shadow on Debian/Ubuntu.
func checkFileOwnerRootRootOrShadow(r Rule, path, fix string) models.CISResult {
	fi, err := os.Stat(path) //nolint:gosec // path is a hardcoded system path
	if err != nil {
		return skipr(r, fmt.Sprintf("%s not found", path))
	}
	stat, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		return skipr(r, fmt.Sprintf("cannot determine ownership of %s", path))
	}
	if stat.Uid != 0 {
		return failr(r, fmt.Sprintf("%s not owned by root (uid=%d)", path, stat.Uid), fix)
	}
	if stat.Gid == 0 {
		return pass(r)
	}
	// Accept shadow group GID (42 on Debian/Ubuntu — look up dynamically)
	if g, err := user.LookupGroup("shadow"); err == nil {
		if gid, err := strconv.ParseUint(g.Gid, 10, 32); err == nil && stat.Gid == uint32(gid) { //nolint:gosec // G115: gid is a non-negative group ID, conversion is safe
			return pass(r)
		}
	}
	return failr(r, fmt.Sprintf("%s not group root or shadow (gid=%d)", path, stat.Gid), fix)
}

// checkServiceNotInstalled passes when none of binPaths exist on the filesystem.
// Used by the "ensure <service> is not installed" rules (2.2.x, 2.3.x): finding
// any binary at one of the paths means the service is installed → FAIL.
func checkServiceNotInstalled(r Rule, binPaths []string, fix string) models.CISResult {
	for _, p := range binPaths {
		if _, err := os.Stat(p); err == nil { //nolint:gosec // path is a package var, not user input
			return failr(r, fmt.Sprintf("binary found: %s", p), fix)
		}
	}
	return pass(r)
}

// checkModuleDisabled verifies that a Linux kernel module is not loaded and is
// configured as disabled in /etc/modprobe.d/. Returns SKIP when /proc/modules
// is unreadable (non-Linux system). Returns FAIL when the module is loaded or
// when no disable configuration exists (module could load on demand).
func checkModuleDisabled(r Rule, module, fix string) models.CISResult {
	modulesData, err := os.ReadFile(procModulesPath) //nolint:gosec // package-level var
	if err != nil {
		return skipr(r, fmt.Sprintf("could not read %s (not a Linux system)", procModulesPath))
	}
	for line := range strings.SplitSeq(string(modulesData), "\n") {
		if strings.HasPrefix(line, module+" ") {
			return failr(r, fmt.Sprintf("kernel module %q is currently loaded", module), fix)
		}
	}
	// Module not loaded — verify it is explicitly disabled so it cannot load on demand
	entries, err := os.ReadDir(modprobeDPath) //nolint:gosec // package-level var
	if err == nil {
		for _, e := range entries {
			if e.IsDir() || !strings.HasSuffix(e.Name(), ".conf") {
				continue
			}
			confData, err := os.ReadFile(filepath.Join(modprobeDPath, e.Name())) //nolint:gosec
			if err != nil {
				continue
			}
			for line := range strings.SplitSeq(string(confData), "\n") {
				line = strings.TrimSpace(line)
				if strings.HasPrefix(line, "install "+module+" /bin/true") ||
					strings.HasPrefix(line, "blacklist "+module) {
					return pass(r)
				}
			}
		}
	}
	return failr(r, fmt.Sprintf("no modprobe disable config for %q (module can load on demand)", module), fix)
}

// checkMountOption verifies that mountPoint appears in /proc/mounts with the
// given mount option (e.g. nodev, nosuid, noexec). Returns SKIP when the mount
// point is not found (may not be a separate partition).
func checkMountOption(r Rule, mountPoint, option, fix string) models.CISResult {
	data, err := os.ReadFile(procMountsPath) //nolint:gosec // package-level var
	if err != nil {
		return skipr(r, fmt.Sprintf("could not read %s", procMountsPath))
	}
	for line := range strings.SplitSeq(string(data), "\n") {
		fields := strings.Fields(line)
		if len(fields) < 4 || fields[1] != mountPoint {
			continue
		}
		for opt := range strings.SplitSeq(fields[3], ",") {
			if opt == option {
				return pass(r)
			}
		}
		return failr(r, fmt.Sprintf("%s is mounted without '%s' option", mountPoint, option), fix)
	}
	return skipr(r, fmt.Sprintf("%s not found as a separate mount (option check skipped)", mountPoint))
}

// checkSeparateMountPoint verifies that mountPoint appears as its own entry in
// /proc/mounts (i.e. is on a separate partition or tmpfs). Returns FAIL when it
// is served by the root filesystem.
func checkSeparateMountPoint(r Rule, mountPoint, fix string) models.CISResult {
	data, err := os.ReadFile(procMountsPath) //nolint:gosec // package-level var
	if err != nil {
		return skipr(r, fmt.Sprintf("could not read %s", procMountsPath))
	}
	for line := range strings.SplitSeq(string(data), "\n") {
		fields := strings.Fields(line)
		if len(fields) >= 2 && fields[1] == mountPoint {
			return pass(r)
		}
	}
	return failr(r, fmt.Sprintf("%s is not on a separate partition", mountPoint), fix)
}

// checkAuditRule verifies that audit configuration files contain at least one
// line matching any of patterns. It reads all *.rules files in auditRulesDPath
// and auditRulesFilePath. Returns SKIP when no audit rule files are readable
// (auditd not installed / non-Linux).
func checkAuditRule(r Rule, patterns []string, fix string) models.CISResult {
	var lines []string

	if data, err := os.ReadFile(auditRulesFilePath); err == nil { //nolint:gosec // package-level var
		for line := range strings.SplitSeq(string(data), "\n") {
			lines = append(lines, line)
		}
	}

	if entries, err := os.ReadDir(auditRulesDPath); err == nil { //nolint:gosec // package-level var
		for _, e := range entries {
			if e.IsDir() || !strings.HasSuffix(e.Name(), ".rules") {
				continue
			}
			data, err := os.ReadFile(filepath.Join(auditRulesDPath, e.Name())) //nolint:gosec
			if err != nil {
				continue
			}
			for line := range strings.SplitSeq(string(data), "\n") {
				lines = append(lines, line)
			}
		}
	}

	if len(lines) == 0 {
		return skipr(r, "no audit rule files found (auditd not configured)")
	}

	for _, pattern := range patterns {
		for _, line := range lines {
			line = strings.TrimSpace(line)
			if strings.HasPrefix(line, "#") || line == "" {
				continue
			}
			if strings.Contains(line, pattern) {
				return pass(r)
			}
		}
	}
	return failr(r, fmt.Sprintf("required audit rule pattern not found: %s", patterns[0]), fix)
}

// ruleByID returns the Rule struct for the given ID by scanning CISRules.
// Must be called only from within a Check function (after init completes).
func ruleByID(id string) Rule {
	for _, r := range CISRules {
		if r.ID == id {
			return r
		}
	}
	return Rule{ID: id, Framework: cisBenchCIS, Description: id}
}

// Evaluate runs all matching rules and returns a CISReport.
// When stig=true, results are presented with STIG IDs and descriptions.
// sshConfigUnverified reports that the SSH config was NOT actually read — neither
// `sshd -T` (needs root) nor the sshd_config file (often mode 0600) succeeded.
// SSH rules read fields that hold secure OpenSSH defaults in that state, so a PASS
// would be unverified. Mirrors checkSecurity's NeedsRoot/SSHConfigUnreadable INFO.
func sshConfigUnverified(sec models.SecurityInfo) bool {
	return sec.SSHConfigUnreadable && sec.SSHAuditSource == ""
}

// Distro-specific remediation helpers (auditInstallCmd/auditRulesCmd/
// adaptRemediation) live in remediation.go — the single sanctioned home for
// package-manager commands and sample-rule paths. See the note there.

func Evaluate(sec models.SecurityInfo, ks models.KernelSecurityInfo, level int, stig bool, pkgMgr string) models.CISReport {
	framework := cisBenchCIS
	if stig {
		framework = cisBenchSTIG
	}
	report := models.CISReport{Framework: framework}

	// IDs owned by a dedicated STIG-framework rule. In STIG mode a BOTH rule
	// whose StigID matches one of these is SUPERSEDED by the dedicated (usually
	// stricter) STIG rule — running both emitted two results with the same STIG
	// ID and contradictory verdicts (e.g. V-238380: CIS 365-day vs STIG 60-day).
	stigOwned := map[string]bool{}
	if stig {
		for _, r := range CISRules {
			if r.Framework == cisBenchSTIG {
				stigOwned[r.ID] = true
			}
		}
	}

	for _, rule := range CISRules {
		if rule.Level > level {
			continue
		}
		// Filter by framework: run CIS rules always; run STIG rules only in STIG mode;
		// run BOTH rules always.
		if stig {
			if rule.Framework == cisBenchCIS {
				continue // CIS-only rule — skip in STIG mode
			}
			if rule.Framework == cisBenchBOTH && rule.StigID != "" && stigOwned[rule.StigID] {
				continue // superseded by a dedicated STIG rule of the same ID
			}
		} else {
			if rule.Framework == cisBenchSTIG {
				continue // STIG-only rule — skip in CIS mode
			}
		}

		result := adaptRemediation(rule.Check(sec, ks), pkgMgr)

		// SSH config-derived rules read fields that fall back to OpenSSH defaults
		// when sshd_config couldn't be read (non-root: `sshd -T` needs root and
		// sshd_config is mode 0600). In that state the verdict is unverified in
		// BOTH directions — a secure default reads PASS ("certified" SSH we never
		// read, a false-OK) and an insecure default reads FAIL ("MaxAuthTries 6"
		// when the admin may have set 4, a false alarm). Report the whole SSH
		// section Skipped so the benchmark neither certifies nor condemns what it
		// couldn't see. 5.2.1 checks the file MODE via os.Stat (works non-root),
		// independent of the parsed config, so it stays valid.
		if rule.Section == cisCatSSH && rule.ID != cisRuleSSH52 && sshConfigUnverified(sec) &&
			(result.Status == models.CISPass || result.Status == models.CISFail) {
			result = skipr(rule, "sshd_config not readable (run as root) — SSH setting not verified")
		}

		// 4.1.1 reads AuditRules==-1 as "auditd not installed or not running" — but
		// `auditctl -l` is root-only, so a non-root run gets the SAME -1 sentinel
		// when auditd is actually installed and running fine. Without this gate a
		// fully compliant host FAILs 4.1.1 purely because dsd ran non-root.
		if rule.ID == cisRuleAudit41 && sec.AuditRulesUnreadable {
			result = skipr(rule, "auditctl -l refused (run as root) — auditd install/run state not verified")
		}

		// In STIG mode, swap in STIG ID and description where available
		if stig && rule.StigID != "" {
			result.ID = rule.StigID
			result.Framework = cisBenchSTIG
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
