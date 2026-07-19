package cis

import (
	"fmt"
	"io/fs"
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

// CIS rule shared string constants — extracted to satisfy the no-duplicate-literal policy.
// These strings appear in skip/fail reasons and path references throughout the rule set.
const (
	cisSkipSSHDirUnreadable     = "could not read /etc/ssh"
	cisSkipSSHConfigUnreadable  = "sshd_config unreadable"
	cisSkipDebianOnly           = "rule applies to Debian/Ubuntu systems only"
	cisPathDevShm               = "/dev/shm"
	cisPathVarTmp               = "/var/tmp"
	cisSkipAuditdUnavailable    = "auditd not available"
	cisSkipAuditdConfUnreadable = "auditd.conf not readable"
	cisFixAuditBacklogGrub      = "add 'audit_backlog_limit=8192' to GRUB_CMDLINE_LINUX in /etc/default/grub and run update-grub"
	cisSkipJournaldNotFound     = "journald config not found (systemd not installed)"
	cisSkipSudoersUnreadable    = "sudoers not readable — run as root for full coverage"
	cisFixInactiveUseradd       = "set INACTIVE=30 in /etc/default/useradd"
	cisSkipPasswdUnreadable     = "could not read /etc/passwd"
	cisSkipGroupUnreadable      = "could not read /etc/group"
	cisSkipHomeDirsUnreadable   = "could not access any home directories — run as root for complete check"
	cisHomeNonexistent          = "/nonexistent"
	cisHomeDevNull              = "/dev/null"
)

// parseMaxStartups parses an sshd MaxStartups value ("start:rate:full" or a bare
// "start") into its start, rate, and full limits. A bare value has no random-drop
// throttling, so full == start and rate == 0. ok is false when the value can't be parsed.
func parseMaxStartups(v string) (start, rate, full int, ok bool) {
	parts := strings.Split(strings.TrimSpace(v), ":")
	s, err := strconv.Atoi(parts[0])
	if err != nil {
		return 0, 0, 0, false
	}
	if len(parts) < 3 {
		return s, 0, s, true
	}
	r, err := strconv.Atoi(parts[1])
	if err != nil {
		return 0, 0, 0, false
	}
	f, err := strconv.Atoi(parts[2])
	if err != nil {
		return 0, 0, 0, false
	}
	return s, r, f, true
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

		{ID: "1.5.5", Framework: cisBenchCIS, Level: 1, Section: "Kernel",
			Description: "Ensure hardlink protection is enabled (fs.protected_hardlinks=1)",
			Check: func(_ models.SecurityInfo, _ models.KernelSecurityInfo) models.CISResult {
				r := ruleByID("1.5.5")
				return checkSysctl(r, "/proc/sys/fs/protected_hardlinks", "1",
					"fs.protected_hardlinks=1 is not set — hardlink attacks possible",
					"sysctl -w fs.protected_hardlinks=1 && echo 'fs.protected_hardlinks=1' >> /etc/sysctl.d/99-cis.conf")
			}},

		{ID: "1.5.6", Framework: cisBenchCIS, Level: 1, Section: "Kernel",
			Description: "Ensure symlink protection is enabled (fs.protected_symlinks=1)",
			Check: func(_ models.SecurityInfo, _ models.KernelSecurityInfo) models.CISResult {
				r := ruleByID("1.5.6")
				return checkSysctl(r, "/proc/sys/fs/protected_symlinks", "1",
					"fs.protected_symlinks=1 is not set — symlink attacks possible",
					"sysctl -w fs.protected_symlinks=1 && echo 'fs.protected_symlinks=1' >> /etc/sysctl.d/99-cis.conf")
			}},

		{ID: "1.5.7", Framework: cisBenchCIS, Level: 1, Section: "Kernel",
			Description: "Ensure kernel dmesg access is restricted (kernel.dmesg_restrict=1)",
			Check: func(_ models.SecurityInfo, _ models.KernelSecurityInfo) models.CISResult {
				r := ruleByID("1.5.7")
				return checkSysctl(r, "/proc/sys/kernel/dmesg_restrict", "1",
					"kernel.dmesg_restrict=1 is not set — unprivileged users can read kernel ring buffer",
					"sysctl -w kernel.dmesg_restrict=1 && echo 'kernel.dmesg_restrict=1' >> /etc/sysctl.d/99-cis.conf")
			}},

		{ID: "1.5.8", Framework: cisBenchCIS, Level: 1, Section: "Kernel",
			Description: "Ensure perf event access is restricted (kernel.perf_event_paranoid >= 1)",
			Check: func(_ models.SecurityInfo, _ models.KernelSecurityInfo) models.CISResult {
				r := ruleByID("1.5.8")
				return checkSysctlGE(r, perfEventParanoidPath, 1,
					"kernel.perf_event_paranoid < 1 — unprivileged users can profile the kernel",
					"sysctl -w kernel.perf_event_paranoid=2 && echo 'kernel.perf_event_paranoid=2' >> /etc/sysctl.d/99-cis.conf")
			}},

		{ID: "1.5.9", Framework: cisBenchCIS, Level: 1, Section: "Kernel",
			Description: "Ensure kernel pointer addresses are restricted (kernel.kptr_restrict >= 1)",
			Check: func(_ models.SecurityInfo, _ models.KernelSecurityInfo) models.CISResult {
				r := ruleByID("1.5.9")
				return checkSysctlGE(r, kptrRestrictPath, 1,
					"kernel.kptr_restrict < 1 — kernel symbol addresses exposed via /proc/kallsyms",
					"sysctl -w kernel.kptr_restrict=2 && echo 'kernel.kptr_restrict=2' >> /etc/sysctl.d/99-cis.conf")
			}},

		{ID: "1.5.10", Framework: cisBenchCIS, Level: 1, Section: "Kernel",
			Description: "Ensure ptrace is restricted to parent process (kernel.yama.ptrace_scope >= 1)",
			Check: func(_ models.SecurityInfo, _ models.KernelSecurityInfo) models.CISResult {
				r := ruleByID("1.5.10")
				return checkSysctlGE(r, yamaPtraceScopePath, 1,
					"kernel.yama.ptrace_scope < 1 — any process can ptrace any other process it owns",
					"sysctl -w kernel.yama.ptrace_scope=1 && echo 'kernel.yama.ptrace_scope=1' >> /etc/sysctl.d/99-cis.conf")
			}},

		{ID: "1.5.11", Framework: cisBenchCIS, Level: 1, Section: "Kernel",
			Description: "Ensure BPF JIT hardening is enabled (net.core.bpf_jit_harden=2)",
			Check: func(_ models.SecurityInfo, _ models.KernelSecurityInfo) models.CISResult {
				r := ruleByID("1.5.11")
				return checkSysctl(r, bpfJitHardenPath, "2",
					"net.core.bpf_jit_harden != 2 — BPF JIT not fully hardened (JIT spraying possible)",
					"sysctl -w net.core.bpf_jit_harden=2 && echo 'net.core.bpf_jit_harden=2' >> /etc/sysctl.d/99-cis.conf")
			}},

		{ID: "1.5.12", Framework: cisBenchCIS, Level: 1, Section: "Kernel",
			Description: "Ensure minimum mmap address is restricted (vm.mmap_min_addr >= 65536)",
			Check: func(_ models.SecurityInfo, _ models.KernelSecurityInfo) models.CISResult {
				r := ruleByID("1.5.12")
				return checkSysctlGE(r, mmapMinAddrPath, 65536,
					"vm.mmap_min_addr < 65536 — processes can mmap near null address (null-pointer deref exploits easier)",
					"sysctl -w vm.mmap_min_addr=65536 && echo 'vm.mmap_min_addr=65536' >> /etc/sysctl.d/99-cis.conf")
			}},
		{ID: "1.5.14", Framework: cisBenchCIS, Level: 1, Section: "Kernel",
			Description: "Ensure SysRq key is disabled (kernel.sysrq = 0)",
			Check: func(_ models.SecurityInfo, _ models.KernelSecurityInfo) models.CISResult {
				r := ruleByID("1.5.14")
				return checkSysctl(r, sysrqPath, "0",
					"kernel.sysrq is not 0 — SysRq keys enable privileged kernel operations (reboot, kill, sync) from the console",
					"sysctl -w kernel.sysrq=0 && echo 'kernel.sysrq=0' >> /etc/sysctl.d/99-cis.conf")
			}},
		{ID: "1.5.15", Framework: cisBenchCIS, Level: 1, Section: "Kernel",
			Description: "Ensure PID is included in core dump filename (kernel.core_uses_pid = 1)",
			Check: func(_ models.SecurityInfo, _ models.KernelSecurityInfo) models.CISResult {
				r := ruleByID("1.5.15")
				return checkSysctl(r, coreUsesPidPath, "1",
					"kernel.core_uses_pid is not 1 — core dumps do not include PID, concurrent dumps may overwrite each other",
					"sysctl -w kernel.core_uses_pid=1 && echo 'kernel.core_uses_pid=1' >> /etc/sysctl.d/99-cis.conf")
			}},
		{ID: "1.5.16", Framework: cisBenchCIS, Level: 1, Section: "Kernel",
			Description: "Ensure regular file creation in sticky dirs is restricted (fs.protected_regular >= 1)",
			Check: func(_ models.SecurityInfo, _ models.KernelSecurityInfo) models.CISResult {
				r := ruleByID("1.5.16")
				return checkSysctlGE(r, protectedRegularPath, 1,
					"fs.protected_regular < 1 — unprivileged users can create regular files in sticky world-writable dirs owned by others",
					"sysctl -w fs.protected_regular=2 && echo 'fs.protected_regular=2' >> /etc/sysctl.d/99-cis.conf")
			}},
		{ID: "1.5.17", Framework: cisBenchCIS, Level: 1, Section: "Kernel",
			Description: "Ensure FIFO creation in sticky dirs is restricted (fs.protected_fifos >= 1)",
			Check: func(_ models.SecurityInfo, _ models.KernelSecurityInfo) models.CISResult {
				r := ruleByID("1.5.17")
				return checkSysctlGE(r, protectedFifosPath, 1,
					"fs.protected_fifos < 1 — unprivileged users can create FIFOs in sticky world-writable dirs owned by others",
					"sysctl -w fs.protected_fifos=2 && echo 'fs.protected_fifos=2' >> /etc/sysctl.d/99-cis.conf")
			}},
		{ID: "1.5.18", Framework: cisBenchCIS, Level: 1, Section: "Kernel",
			Description: "Ensure unprivileged BPF is disabled (kernel.unprivileged_bpf_disabled >= 1)",
			Check: func(_ models.SecurityInfo, _ models.KernelSecurityInfo) models.CISResult {
				r := ruleByID("1.5.18")
				return checkSysctlGE(r, unprivilegedBpfDisabledPath, 1,
					"kernel.unprivileged_bpf_disabled < 1 — unprivileged users can load BPF programs (privilege escalation risk)",
					"sysctl -w kernel.unprivileged_bpf_disabled=1 && echo 'kernel.unprivileged_bpf_disabled=1' >> /etc/sysctl.d/99-cis.conf")
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

		{ID: "2.2.5", Framework: cisBenchCIS, Level: 1, Section: cisCatServices,
			Description: "Ensure LDAP client is not installed",
			Check: func(_ models.SecurityInfo, _ models.KernelSecurityInfo) models.CISResult {
				return checkServiceNotInstalled(ruleByID("2.2.5"), ldapClientBinPaths,
					"remove LDAP client: apt purge ldap-utils / dnf remove openldap-clients")
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

		{ID: "2.3.14", Framework: cisBenchCIS, Level: 1, Section: cisCatServices,
			Description: "Ensure MTA is configured for local-only mode",
			Check: func(_ models.SecurityInfo, _ models.KernelSecurityInfo) models.CISResult {
				r := ruleByID("2.3.14")
				mtaFound := false
				for _, p := range mtaBinPaths {
					if _, err := os.Stat(p); err == nil {
						mtaFound = true
						break
					}
				}
				if !mtaFound {
					return skipr(r, "no MTA (postfix/sendmail) installed")
				}
				data, err := os.ReadFile(postfixMainCfPath) // #nosec G304 -- package-level var
				if err != nil {
					return skipr(r, "postfix main.cf not readable — cannot verify inet_interfaces")
				}
				for line := range strings.SplitSeq(string(data), "\n") {
					trimmed := strings.TrimSpace(line)
					if trimmed == "" || strings.HasPrefix(trimmed, "#") {
						continue
					}
					rest, ok := strings.CutPrefix(trimmed, "inet_interfaces")
					if !ok {
						continue
					}
					rest = strings.TrimSpace(rest)
					rest, ok = strings.CutPrefix(rest, "=")
					if !ok {
						continue
					}
					val := strings.ToLower(strings.TrimSpace(rest))
					if val == "loopback-only" || val == "localhost" {
						return pass(r)
					}
					return failr(r,
						fmt.Sprintf("inet_interfaces = %q — MTA accepts external connections", val),
						"set inet_interfaces = loopback-only in /etc/postfix/main.cf and run: postfix reload")
				}
				return failr(r, "inet_interfaces not set in /etc/postfix/main.cf",
					"add inet_interfaces = loopback-only to /etc/postfix/main.cf and run: postfix reload")
			}},

		{ID: "2.3.15", Framework: cisBenchCIS, Level: 1, Section: cisCatServices,
			Description: "Ensure rsync service is not enabled",
			Check: func(_ models.SecurityInfo, _ models.KernelSecurityInfo) models.CISResult {
				r := ruleByID("2.3.15")
				rsyncPresent := false
				for _, p := range rsyncBinPaths {
					if _, err := os.Stat(p); err == nil {
						rsyncPresent = true
						break
					}
				}
				if !rsyncPresent {
					return skipr(r, "rsync not installed")
				}
				for _, p := range rsyncWantsPaths {
					if _, err := os.Stat(p); err == nil {
						return failr(r, "rsync daemon is enabled via systemd",
							"systemctl disable rsync && systemctl stop rsync")
					}
				}
				data, err := os.ReadFile(rsyncDefaultPath) // #nosec G304 -- package-level var
				if err == nil {
					for line := range strings.SplitSeq(string(data), "\n") {
						trimmed := strings.TrimSpace(line)
						if trimmed == "" || strings.HasPrefix(trimmed, "#") {
							continue
						}
						rest, ok := strings.CutPrefix(trimmed, "RSYNC_ENABLE=")
						if !ok {
							continue
						}
						val := strings.Trim(rest, "\"'")
						if strings.EqualFold(val, "true") || val == "1" {
							return failr(r,
								"RSYNC_ENABLE=true in /etc/default/rsync — rsync daemon is enabled",
								"set RSYNC_ENABLE=false in /etc/default/rsync")
						}
					}
				}
				return pass(r)
			}},

		{ID: "2.3.16", Framework: cisBenchCIS, Level: 1, Section: cisCatServices,
			Description: "Ensure NIS server is not installed",
			Check: func(_ models.SecurityInfo, _ models.KernelSecurityInfo) models.CISResult {
				return checkServiceNotInstalled(ruleByID("2.3.16"), nisServerBinPaths,
					"remove NIS server: apt purge nis / dnf remove ypserv")
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

		{ID: "5.2.3", Framework: cisBenchCIS, Level: 1, Section: cisCatSSH,
			Description: "Ensure permissions on SSH public host key files are configured (max 0644)",
			Check: func(_ models.SecurityInfo, _ models.KernelSecurityInfo) models.CISResult {
				r := ruleByID("5.2.3")
				entries, err := os.ReadDir(sshHostKeyDir) //nolint:gosec // package-level var
				if err != nil {
					return skipr(r, cisSkipSSHDirUnreadable)
				}
				var bad []string
				found := false
				for _, e := range entries {
					name := e.Name()
					if !strings.HasPrefix(name, "ssh_host_") || !strings.HasSuffix(name, "_key.pub") {
						continue
					}
					found = true
					fi, err := e.Info()
					if err != nil {
						continue
					}
					if fi.Mode().Perm()&^0o644 != 0 {
						bad = append(bad, fmt.Sprintf("%s (%o)", name, fi.Mode().Perm()))
					}
				}
				if !found {
					return skipr(r, "no SSH public host key files found")
				}
				if len(bad) > 0 {
					return failr(r, fmt.Sprintf("SSH public host key files with excessive permissions: %s", strings.Join(bad, ", ")),
						"chmod 644 /etc/ssh/ssh_host_*_key.pub")
				}
				return pass(r)
			}},

		{ID: "5.2.4", Framework: cisBenchCIS, Level: 1, Section: cisCatSSH,
			Description: "Ensure permissions on SSH private host key files are configured (max 0600)",
			Check: func(_ models.SecurityInfo, _ models.KernelSecurityInfo) models.CISResult {
				r := ruleByID("5.2.4")
				entries, err := os.ReadDir(sshHostKeyDir) //nolint:gosec // package-level var
				if err != nil {
					return skipr(r, cisSkipSSHDirUnreadable)
				}
				var bad []string
				found := false
				for _, e := range entries {
					name := e.Name()
					if !strings.HasPrefix(name, "ssh_host_") || strings.HasSuffix(name, ".pub") {
						continue
					}
					if !strings.HasSuffix(name, "_key") {
						continue
					}
					found = true
					fi, err := e.Info()
					if err != nil {
						continue
					}
					if fi.Mode().Perm()&^0o600 != 0 {
						bad = append(bad, fmt.Sprintf("%s (%o)", name, fi.Mode().Perm()))
					}
				}
				if !found {
					return skipr(r, "no SSH private host key files found")
				}
				if len(bad) > 0 {
					return failr(r, fmt.Sprintf("SSH private host key files with excessive permissions: %s", strings.Join(bad, ", ")),
						"chmod 600 /etc/ssh/ssh_host_*_key")
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
				if sec.SSHConfigUnreadable {
					return skipr(r, "sshd_config unreadable")
				}
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
				if sec.SSHConfigUnreadable {
					return skipr(r, "sshd_config not readable — run as root")
				}
				// `sshd -T` always emits MaxStartups (compiled default 10:30:100),
				// so presence alone is not compliance — the value must be within
				// CIS limits (start ≤ 10, full ≤ 60). The OpenSSH default 10:30:100
				// FAILS, so a presence-only check wrongly passed every stock host.
				if sec.SSHMaxStartups == "" {
					return failr(r, "MaxStartups not set (default 10:30:100 allows 100 unauthenticated connections)",
						"set MaxStartups 10:30:60 in /etc/ssh/sshd_config")
				}
				start, _, full, ok := parseMaxStartups(sec.SSHMaxStartups)
				if !ok {
					return skipr(r, fmt.Sprintf("MaxStartups value %q could not be parsed", sec.SSHMaxStartups))
				}
				if start > 10 || full > 60 {
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
		{ID: "5.2.20", Framework: cisBenchCIS, Level: 1, Section: cisCatSSH,
			Description: "Ensure SSH PasswordAuthentication is disabled",
			Check: func(sec models.SecurityInfo, _ models.KernelSecurityInfo) models.CISResult {
				r := ruleByID("5.2.20")
				if sec.SSHConfigUnreadable {
					return skipr(r, cisSkipSSHConfigUnreadable)
				}
				if sec.SSHPasswordAuth {
					return failr(r, "PasswordAuthentication yes — password logins permitted over SSH",
						"set PasswordAuthentication no in /etc/ssh/sshd_config")
				}
				return pass(r)
			}},
		{ID: "5.2.21", Framework: cisBenchCIS, Level: 1, Section: cisCatSSH,
			Description: "Ensure SSH StrictModes is enabled",
			Check: func(sec models.SecurityInfo, _ models.KernelSecurityInfo) models.CISResult {
				r := ruleByID("5.2.21")
				if sec.SSHConfigUnreadable {
					return skipr(r, cisSkipSSHConfigUnreadable)
				}
				if !sec.SSHStrictModes {
					return failr(r, "StrictModes no — SSH ignores file-permission checks on user keys and home dirs",
						"set StrictModes yes in /etc/ssh/sshd_config")
				}
				return pass(r)
			}},
		{ID: "5.2.22", Framework: cisBenchCIS, Level: 1, Section: cisCatSSH,
			Description: "Ensure SSH agent forwarding is disabled",
			Check: func(sec models.SecurityInfo, _ models.KernelSecurityInfo) models.CISResult {
				r := ruleByID("5.2.22")
				if sec.SSHConfigUnreadable {
					return skipr(r, cisSkipSSHConfigUnreadable)
				}
				if sec.SSHAgentForwarding {
					return failr(r, "AllowAgentForwarding yes — SSH agent can be hijacked if this host is compromised",
						"set AllowAgentForwarding no in /etc/ssh/sshd_config")
				}
				return pass(r)
			}},
		{ID: "5.2.23", Framework: cisBenchCIS, Level: 1, Section: cisCatSSH,
			Description: "Ensure SSH Protocol 1 is not enabled",
			Check: func(sec models.SecurityInfo, _ models.KernelSecurityInfo) models.CISResult {
				r := ruleByID("5.2.23")
				if sec.SSHConfigUnreadable {
					return skipr(r, cisSkipSSHConfigUnreadable)
				}
				if sec.SSHProtocol1 {
					return failr(r, "Protocol 1 is enabled — uses obsolete, broken cryptography",
						"remove any 'Protocol' directive (or set 'Protocol 2') from /etc/ssh/sshd_config")
				}
				return pass(r)
			}},
		{ID: "5.2.24", Framework: cisBenchCIS, Level: 1, Section: cisCatSSH,
			Description: "Ensure SSH PubkeyAuthentication is enabled",
			Check: func(sec models.SecurityInfo, _ models.KernelSecurityInfo) models.CISResult {
				r := ruleByID("5.2.24")
				if sec.SSHConfigUnreadable {
					return skipr(r, cisSkipSSHConfigUnreadable)
				}
				if !sec.SSHPubkeyAuth {
					return failr(r, "PubkeyAuthentication no — public-key login disabled, only password auth available",
						"set PubkeyAuthentication yes in /etc/ssh/sshd_config")
				}
				return pass(r)
			}},
		{ID: "5.2.25", Framework: cisBenchCIS, Level: 1, Section: cisCatSSH,
			Description: "Ensure only approved SSH cipher algorithms are used",
			Check: func(sec models.SecurityInfo, _ models.KernelSecurityInfo) models.CISResult {
				r := ruleByID("5.2.25")
				if sec.SSHConfigUnreadable {
					return skipr(r, cisSkipSSHConfigUnreadable)
				}
				if sec.SSHCiphers == "" {
					return skipr(r, "Ciphers not available (run as root for sshd -T)")
				}
				for algo := range strings.SplitSeq(sec.SSHCiphers, ",") {
					algo = strings.ToLower(strings.TrimSpace(algo))
					if strings.HasSuffix(algo, "-cbc") || strings.HasPrefix(algo, "arcfour") ||
						strings.HasPrefix(algo, "3des") || strings.HasPrefix(algo, "blowfish") {
						return failr(r, fmt.Sprintf("weak cipher in Ciphers list: %q", algo),
							"set Ciphers aes128-ctr,aes192-ctr,aes256-ctr,aes128-gcm@openssh.com,aes256-gcm@openssh.com,chacha20-poly1305@openssh.com")
					}
				}
				return pass(r)
			}},
		{ID: "5.2.26", Framework: cisBenchCIS, Level: 1, Section: cisCatSSH,
			Description: "Ensure only approved SSH MAC algorithms are used",
			Check: func(sec models.SecurityInfo, _ models.KernelSecurityInfo) models.CISResult {
				r := ruleByID("5.2.26")
				if sec.SSHConfigUnreadable {
					return skipr(r, cisSkipSSHConfigUnreadable)
				}
				if sec.SSHMACs == "" {
					return skipr(r, "MACs not available (run as root for sshd -T)")
				}
				for algo := range strings.SplitSeq(sec.SSHMACs, ",") {
					algo = strings.ToLower(strings.TrimSpace(algo))
					if strings.Contains(algo, "md5") || strings.Contains(algo, "sha1") ||
						strings.Contains(algo, "ripemd") || strings.HasPrefix(algo, "umac-64") ||
						strings.HasPrefix(algo, "umac-96") {
						return failr(r, fmt.Sprintf("weak MAC in MACs list: %q", algo),
							"set MACs hmac-sha2-256,hmac-sha2-512,hmac-sha2-256-etm@openssh.com,hmac-sha2-512-etm@openssh.com")
					}
				}
				return pass(r)
			}},
		{ID: "5.2.27", Framework: cisBenchCIS, Level: 1, Section: cisCatSSH,
			Description: "Ensure only approved SSH key exchange algorithms are used",
			Check: func(sec models.SecurityInfo, _ models.KernelSecurityInfo) models.CISResult {
				r := ruleByID("5.2.27")
				if sec.SSHConfigUnreadable {
					return skipr(r, cisSkipSSHConfigUnreadable)
				}
				if sec.SSHKexAlgorithms == "" {
					return skipr(r, "KexAlgorithms not available (run as root for sshd -T)")
				}
				for algo := range strings.SplitSeq(sec.SSHKexAlgorithms, ",") {
					algo = strings.ToLower(strings.TrimSpace(algo))
					if strings.Contains(algo, "sha1") || strings.Contains(algo, "group1-") {
						return failr(r, fmt.Sprintf("weak key exchange algorithm: %q", algo),
							"set KexAlgorithms curve25519-sha256,curve25519-sha256@libssh.org,diffie-hellman-group14-sha256,diffie-hellman-group16-sha512,diffie-hellman-group18-sha512,ecdh-sha2-nistp256,ecdh-sha2-nistp384,ecdh-sha2-nistp521")
					}
				}
				return pass(r)
			}},

		// ── 5.2.28-5.2.30 SSH file ownership ─────────────────────────────────

		{ID: "5.2.28", Framework: cisBenchCIS, Level: 1, Section: cisCatSSH,
			Description: "Ensure /etc/ssh/sshd_config is owned by root:root",
			Check: func(_ models.SecurityInfo, _ models.KernelSecurityInfo) models.CISResult {
				return checkFileOwnerRootRoot(ruleByID("5.2.28"), sshdConfigPath, "chown root:root /etc/ssh/sshd_config")
			}},

		{ID: "5.2.29", Framework: cisBenchCIS, Level: 1, Section: cisCatSSH,
			Description: "Ensure SSH public host key files are owned by root:root",
			Check: func(_ models.SecurityInfo, _ models.KernelSecurityInfo) models.CISResult {
				r := ruleByID("5.2.29")
				entries, err := os.ReadDir(sshHostKeyDir) //nolint:gosec // package-level var
				if err != nil {
					return skipr(r, cisSkipSSHDirUnreadable)
				}
				var bad []string
				found := false
				for _, e := range entries {
					name := e.Name()
					if !strings.HasPrefix(name, "ssh_host_") || !strings.HasSuffix(name, "_key.pub") {
						continue
					}
					found = true
					fi, err := e.Info()
					if err != nil {
						continue
					}
					stat, ok := fi.Sys().(*syscall.Stat_t)
					if !ok {
						continue // cannot check ownership on this OS; skip file
					}
					if stat.Uid != 0 || stat.Gid != 0 {
						bad = append(bad, fmt.Sprintf("%s (uid=%d gid=%d)", name, stat.Uid, stat.Gid))
					}
				}
				if !found {
					return skipr(r, "no SSH public host key files found")
				}
				if len(bad) > 0 {
					return failr(r, fmt.Sprintf("SSH public host key files not owned by root:root: %s", strings.Join(bad, ", ")),
						"chown root:root /etc/ssh/ssh_host_*_key.pub")
				}
				return pass(r)
			}},

		{ID: "5.2.30", Framework: cisBenchCIS, Level: 1, Section: cisCatSSH,
			Description: "Ensure SSH private host key files are owned by root:root",
			Check: func(_ models.SecurityInfo, _ models.KernelSecurityInfo) models.CISResult {
				r := ruleByID("5.2.30")
				entries, err := os.ReadDir(sshHostKeyDir) //nolint:gosec // package-level var
				if err != nil {
					return skipr(r, cisSkipSSHDirUnreadable)
				}
				var bad []string
				found := false
				for _, e := range entries {
					name := e.Name()
					if !strings.HasPrefix(name, "ssh_host_") || strings.HasSuffix(name, ".pub") {
						continue
					}
					if !strings.HasSuffix(name, "_key") {
						continue
					}
					found = true
					fi, err := e.Info()
					if err != nil {
						continue
					}
					stat, ok := fi.Sys().(*syscall.Stat_t)
					if !ok {
						continue // cannot check ownership on this OS; skip file
					}
					if stat.Uid != 0 || stat.Gid != 0 {
						bad = append(bad, fmt.Sprintf("%s (uid=%d gid=%d)", name, stat.Uid, stat.Gid))
					}
				}
				if !found {
					return skipr(r, "no SSH private host key files found")
				}
				if len(bad) > 0 {
					return failr(r, fmt.Sprintf("SSH private host key files not owned by root:root: %s", strings.Join(bad, ", ")),
						"chown root:root /etc/ssh/ssh_host_*_key")
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
		{ID: "3.1.3", Framework: cisBenchCIS, Level: 1, Section: cisCatNetwork,
			Description: "Ensure packet redirect sending is disabled on default interface (net.ipv4.conf.default.send_redirects = 0)",
			Check: func(_ models.SecurityInfo, _ models.KernelSecurityInfo) models.CISResult {
				r := ruleByID("3.1.3")
				return checkSysctl(r, "/proc/sys/net/ipv4/conf/default/send_redirects", "0",
					"net.ipv4.conf.default.send_redirects is not 0 — new interfaces will send ICMP redirects",
					"sysctl -w net.ipv4.conf.default.send_redirects=0 && echo 'net.ipv4.conf.default.send_redirects=0' >> /etc/sysctl.d/99-cis.conf")
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

		// ── 1.2 Software Updates ─────────────────────────────────────────────
		// These rules are Debian/Ubuntu-specific: RHEL/SUSE/Arch use different
		// repository and keyring paths. Gate on /etc/debian_version to SKIP gracefully.

		{ID: "1.2.1", Framework: cisBenchCIS, Level: 1, Section: "Filesystem",
			Description: "Ensure package manager repositories are configured",
			Check: func(_ models.SecurityInfo, _ models.KernelSecurityInfo) models.CISResult {
				r := ruleByID("1.2.1")
				if _, err := os.Stat(debianVersionPath); err != nil {
					return skipr(r, cisSkipDebianOnly)
				}
				data, err := os.ReadFile(aptSourcesListPath) // #nosec G304 -- package-level var
				if err == nil {
					for line := range strings.SplitSeq(string(data), "\n") {
						trimmed := strings.TrimSpace(line)
						if trimmed != "" && !strings.HasPrefix(trimmed, "#") {
							return pass(r)
						}
					}
				}
				entries, err := os.ReadDir(aptSourcesListDPath) //nolint:gosec // package-level var
				if err == nil {
					for _, e := range entries {
						name := e.Name()
						if strings.HasSuffix(name, ".list") || strings.HasSuffix(name, ".sources") {
							return pass(r)
						}
					}
				}
				return failr(r, "no apt repositories configured",
					"configure apt repositories in /etc/apt/sources.list or /etc/apt/sources.list.d/")
			}},

		{ID: "1.2.2", Framework: cisBenchCIS, Level: 1, Section: "Filesystem",
			Description: "Ensure GPG keys are configured",
			Check: func(_ models.SecurityInfo, _ models.KernelSecurityInfo) models.CISResult {
				r := ruleByID("1.2.2")
				if _, err := os.Stat(debianVersionPath); err != nil {
					return skipr(r, cisSkipDebianOnly)
				}
				if _, err := os.Stat(aptTrustedGpgPath); err == nil {
					return pass(r)
				}
				entries, err := os.ReadDir(aptTrustedGpgDPath) //nolint:gosec // package-level var
				if err == nil && len(entries) > 0 {
					return pass(r)
				}
				entries2, err := os.ReadDir(aptKeyringsPath) //nolint:gosec // package-level var
				if err == nil && len(entries2) > 0 {
					return pass(r)
				}
				return failr(r, "no GPG keys found for apt repositories",
					"verify apt GPG keys: apt-key list or inspect /etc/apt/trusted.gpg.d/ and /etc/apt/keyrings/")
			}},

		{ID: "1.2.3", Framework: cisBenchCIS, Level: 1, Section: "Filesystem",
			Description: "Ensure package manager is not configured to allow unauthenticated packages",
			Check: func(_ models.SecurityInfo, _ models.KernelSecurityInfo) models.CISResult {
				r := ruleByID("1.2.3")
				if _, err := os.Stat(debianVersionPath); err != nil {
					return skipr(r, cisSkipDebianOnly)
				}
				entries, err := os.ReadDir(aptConfDPath) //nolint:gosec // package-level var
				if err != nil {
					return pass(r) // no apt.conf.d = default (authenticated)
				}
				for _, e := range entries {
					if e.IsDir() || !strings.HasSuffix(e.Name(), ".conf") {
						continue
					}
					data, rdErr := os.ReadFile(filepath.Join(aptConfDPath, e.Name())) //nolint:gosec
					if rdErr != nil {
						continue
					}
					for line := range strings.SplitSeq(string(data), "\n") {
						line = strings.TrimSpace(line)
						if strings.HasPrefix(line, "//") || strings.HasPrefix(line, "#") {
							continue
						}
						lower := strings.ToLower(line)
						if strings.Contains(lower, "allowunauthenticated") && strings.Contains(lower, "true") {
							return failr(r, fmt.Sprintf("AllowUnauthenticated = true found in %s", e.Name()),
								"remove or set AllowUnauthenticated \"false\" in /etc/apt/apt.conf.d/")
						}
					}
				}
				return pass(r)
			}},

		{ID: "1.2.4", Framework: cisBenchCIS, Level: 1, Section: "Filesystem",
			Description: "Ensure software updates are applied automatically (unattended-upgrades)",
			Check: func(_ models.SecurityInfo, _ models.KernelSecurityInfo) models.CISResult {
				r := ruleByID("1.2.4")
				if _, err := os.Stat(debianVersionPath); err != nil {
					return skipr(r, cisSkipDebianOnly)
				}
				for _, p := range unattendedUpgradesBinPaths {
					if _, err := os.Stat(p); err == nil { //nolint:gosec // package-level var
						return pass(r)
					}
				}
				return failr(r, "unattended-upgrades not installed",
					unattendedUpgradesInstallCmd("apt"))
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
				return checkMountOption(ruleByID("1.1.6"), cisPathDevShm, "nodev",
					"add 'nodev' to /dev/shm mount options in /etc/fstab")
			}},

		{ID: "1.1.7", Framework: cisBenchCIS, Level: 1, Section: "Filesystem",
			Description: "Ensure nosuid option set on /dev/shm partition",
			Check: func(_ models.SecurityInfo, _ models.KernelSecurityInfo) models.CISResult {
				return checkMountOption(ruleByID("1.1.7"), cisPathDevShm, "nosuid",
					"add 'nosuid' to /dev/shm mount options in /etc/fstab")
			}},

		{ID: "1.1.8", Framework: cisBenchCIS, Level: 1, Section: "Filesystem",
			Description: "Ensure noexec option set on /dev/shm partition",
			Check: func(_ models.SecurityInfo, _ models.KernelSecurityInfo) models.CISResult {
				return checkMountOption(ruleByID("1.1.8"), cisPathDevShm, "noexec",
					"add 'noexec' to /dev/shm mount options in /etc/fstab")
			}},

		{ID: "1.1.9", Framework: cisBenchCIS, Level: 1, Section: "Filesystem",
			Description: "Ensure nodev option set on /var/tmp partition",
			Check: func(_ models.SecurityInfo, _ models.KernelSecurityInfo) models.CISResult {
				return checkMountOption(ruleByID("1.1.9"), cisPathVarTmp, "nodev",
					"add 'nodev' to /var/tmp mount options in /etc/fstab")
			}},

		{ID: "1.1.10", Framework: cisBenchCIS, Level: 1, Section: "Filesystem",
			Description: "Ensure nosuid option set on /var/tmp partition",
			Check: func(_ models.SecurityInfo, _ models.KernelSecurityInfo) models.CISResult {
				return checkMountOption(ruleByID("1.1.10"), cisPathVarTmp, "nosuid",
					"add 'nosuid' to /var/tmp mount options in /etc/fstab")
			}},

		{ID: "1.1.11", Framework: cisBenchCIS, Level: 1, Section: "Filesystem",
			Description: "Ensure noexec option set on /var/tmp partition",
			Check: func(_ models.SecurityInfo, _ models.KernelSecurityInfo) models.CISResult {
				return checkMountOption(ruleByID("1.1.11"), cisPathVarTmp, "noexec",
					"add 'noexec' to /var/tmp mount options in /etc/fstab")
			}},

		{ID: "1.1.12", Framework: cisBenchCIS, Level: 2, Section: "Filesystem",
			Description: "Ensure /var/log directory is on its own filesystem",
			Check: func(_ models.SecurityInfo, _ models.KernelSecurityInfo) models.CISResult {
				return checkSeparateMountPoint(ruleByID("1.1.12"), varLogPath,
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

		{ID: "1.1.17", Framework: cisBenchCIS, Level: 2, Section: "Filesystem",
			Description: "Ensure USB storage is disabled",
			Check: func(_ models.SecurityInfo, _ models.KernelSecurityInfo) models.CISResult {
				return checkModuleDisabled(ruleByID("1.1.17"), "usb-storage",
					"echo 'install usb-storage /bin/true' > /etc/modprobe.d/usb-storage.conf && echo 'blacklist usb-storage' >> /etc/modprobe.d/usb-storage.conf")
			}},

		{ID: "1.1.18", Framework: cisBenchCIS, Level: 2, Section: "Filesystem",
			Description: "Ensure automounting is disabled",
			Check: func(_ models.SecurityInfo, _ models.KernelSecurityInfo) models.CISResult {
				return checkModuleDisabled(ruleByID("1.1.18"), "autofs",
					"echo 'install autofs /bin/true' > /etc/modprobe.d/autofs.conf && echo 'blacklist autofs' >> /etc/modprobe.d/autofs.conf")
			}},

		// ── 1.5.2 Prelink ─────────────────────────────────────────────────────────

		{ID: "1.5.2", Framework: cisBenchCIS, Level: 1, Section: "Kernel",
			Description: "Ensure prelink is not installed",
			Check: func(_ models.SecurityInfo, _ models.KernelSecurityInfo) models.CISResult {
				return checkServiceNotInstalled(ruleByID("1.5.2"), prelinkBinPaths,
					"apt purge prelink / dnf remove prelink")
			}},

		{ID: "1.5.3", Framework: cisBenchCIS, Level: 1, Section: "Kernel",
			Description: "Ensure automatic error reporting (apport) is not enabled",
			Check: func(_ models.SecurityInfo, _ models.KernelSecurityInfo) models.CISResult {
				r := ruleByID("1.5.3")
				installed := false
				for _, p := range apportBinPaths {
					if _, err := os.Stat(p); err == nil { //nolint:gosec // package-level var
						installed = true
						break
					}
				}
				if !installed {
					return pass(r)
				}
				data, err := os.ReadFile(apportDefaultPath) //nolint:gosec // package-level var
				if err != nil {
					return failr(r, "apport installed but /etc/default/apport unreadable or missing",
						"echo 'enabled=0' > /etc/default/apport")
				}
				for line := range strings.SplitSeq(string(data), "\n") {
					line = strings.TrimSpace(line)
					if line == "enabled=0" {
						return pass(r)
					}
				}
				return failr(r, "apport is installed and not disabled (enabled=0 not found in /etc/default/apport)",
					"echo 'enabled=0' > /etc/default/apport")
			}},

		// ── 1.6 Mandatory Access Control (AppArmor) ──────────────────────────

		{ID: "1.6.1", Framework: cisBenchCIS, Level: 1, Section: "AppArmor",
			Description: "Ensure AppArmor is installed",
			Check: func(_ models.SecurityInfo, _ models.KernelSecurityInfo) models.CISResult {
				r := ruleByID("1.6.1")
				for _, p := range apparmorParserPaths {
					if _, err := os.Stat(p); err == nil { // #nosec G304 -- hardcoded system paths
						return pass(r)
					}
				}
				return failr(r, "apparmor_parser not found — AppArmor may not be installed",
					apparmorInstallCmd("apt"))
			}},

		{ID: "1.6.2", Framework: cisBenchCIS, Level: 1, Section: "AppArmor",
			Description: "Ensure AppArmor is enabled in the bootloader configuration",
			Check: func(_ models.SecurityInfo, _ models.KernelSecurityInfo) models.CISResult {
				r := ruleByID("1.6.2")
				data, err := os.ReadFile(grubDefaultPath) // #nosec G304 -- hardcoded system path
				if err != nil {
					return skipr(r, "could not read /etc/default/grub")
				}
				for line := range strings.SplitSeq(string(data), "\n") {
					line = strings.TrimSpace(line)
					if strings.HasPrefix(line, "#") || !strings.HasPrefix(line, "GRUB_CMDLINE_LINUX=") {
						continue
					}
					// Extract the cmdline value (strip surrounding quotes).
					val := strings.TrimPrefix(line, "GRUB_CMDLINE_LINUX=")
					val = strings.Trim(val, `"'`)
					// Token-split so "apparmor=10" does not satisfy "apparmor=1".
					tokens := strings.Fields(val)
					hasAA, hasSec := false, false
					for _, tok := range tokens {
						if tok == "apparmor=1" {
							hasAA = true
						}
						if tok == "security=apparmor" {
							hasSec = true
						}
					}
					if hasAA && hasSec {
						return pass(r)
					}
					return failr(r,
						"GRUB_CMDLINE_LINUX does not contain 'apparmor=1 security=apparmor'",
						"add 'apparmor=1 security=apparmor' to GRUB_CMDLINE_LINUX in /etc/default/grub, then run update-grub")
				}
				return skipr(r, "GRUB_CMDLINE_LINUX not found in /etc/default/grub")
			}},

		{ID: "1.6.3", Framework: cisBenchCIS, Level: 1, Section: "AppArmor",
			Description: "Ensure all AppArmor Profiles are in enforce or complain mode",
			Check: func(_ models.SecurityInfo, _ models.KernelSecurityInfo) models.CISResult {
				r := ruleByID("1.6.3")
				data, err := os.ReadFile(apparmorProfilesPath) // #nosec G304 -- hardcoded securityfs path
				if err != nil {
					return skipr(r, "could not read AppArmor profiles — AppArmor kernel support may be absent")
				}
				count := 0
				for line := range strings.SplitSeq(string(data), "\n") {
					if strings.TrimSpace(line) != "" {
						count++
					}
				}
				if count == 0 {
					return failr(r, "no AppArmor profiles are loaded",
						"load profiles: apparmor_parser -r /etc/apparmor.d/*")
				}
				return pass(r)
			}},

		{ID: "1.6.4", Framework: cisBenchCIS, Level: 2, Section: "AppArmor",
			Description: "Ensure all AppArmor Profiles are enforcing",
			Check: func(_ models.SecurityInfo, _ models.KernelSecurityInfo) models.CISResult {
				r := ruleByID("1.6.4")
				data, err := os.ReadFile(apparmorProfilesPath) // #nosec G304 -- hardcoded securityfs path
				if err != nil {
					return skipr(r, "could not read AppArmor profiles")
				}
				var complain []string
				for line := range strings.SplitSeq(string(data), "\n") {
					line = strings.TrimSpace(line)
					if line == "" {
						continue
					}
					if strings.HasSuffix(line, "(complain)") {
						name := strings.TrimSuffix(line, " (complain)")
						complain = append(complain, strings.TrimSpace(name))
					}
				}
				if len(complain) > 0 {
					shown := complain[:min(3, len(complain))]
					return failr(r,
						fmt.Sprintf("%d profile(s) in complain mode: %s", len(complain), strings.Join(shown, ", ")),
						"set all profiles to enforce: aa-enforce /etc/apparmor.d/*")
				}
				return pass(r)
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
		{ID: "1.7.7", Framework: cisBenchCIS, Level: 1, Section: "Banners",
			Description: "Ensure /etc/motd is owned by root:root",
			Check: func(_ models.SecurityInfo, _ models.KernelSecurityInfo) models.CISResult {
				return checkFileOwnerRootRoot(ruleByID("1.7.7"), motdPath, "chown root:root /etc/motd")
			}},
		{ID: "1.7.8", Framework: cisBenchCIS, Level: 1, Section: "Banners",
			Description: "Ensure /etc/issue is owned by root:root",
			Check: func(_ models.SecurityInfo, _ models.KernelSecurityInfo) models.CISResult {
				return checkFileOwnerRootRoot(ruleByID("1.7.8"), issuePath, "chown root:root /etc/issue")
			}},
		{ID: "1.7.9", Framework: cisBenchCIS, Level: 1, Section: "Banners",
			Description: "Ensure /etc/issue.net is owned by root:root",
			Check: func(_ models.SecurityInfo, _ models.KernelSecurityInfo) models.CISResult {
				return checkFileOwnerRootRoot(ruleByID("1.7.9"), issueNetPath, "chown root:root /etc/issue.net")
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

		{ID: "3.2.9", Framework: cisBenchCIS, Level: 1, Section: cisCatNetwork,
			Description: "Ensure IPv6 router advertisements are not accepted",
			Check: func(_ models.SecurityInfo, _ models.KernelSecurityInfo) models.CISResult {
				r := ruleByID("3.2.9")
				return checkSysctl(r, "/proc/sys/net/ipv6/conf/all/accept_ra", "0",
					"net.ipv6.conf.all.accept_ra is not 0 — IPv6 router advertisements accepted",
					"sysctl -w net.ipv6.conf.all.accept_ra=0 && sysctl -w net.ipv6.conf.default.accept_ra=0")
			}},

		{ID: "3.2.10", Framework: cisBenchCIS, Level: 1, Section: cisCatNetwork,
			Description: "Ensure IPv6 redirects are not accepted",
			Check: func(_ models.SecurityInfo, _ models.KernelSecurityInfo) models.CISResult {
				r := ruleByID("3.2.10")
				return checkSysctl(r, "/proc/sys/net/ipv6/conf/all/accept_redirects", "0",
					"net.ipv6.conf.all.accept_redirects is not 0 — IPv6 ICMP redirects accepted",
					"sysctl -w net.ipv6.conf.all.accept_redirects=0 && sysctl -w net.ipv6.conf.default.accept_redirects=0")
			}},

		// ── 3.2.11-3.2.18 default/ interface sysctl companions ───────────────────
		// Each mirrors its all/ counterpart: new interfaces inherit default/ settings.

		{ID: "3.2.11", Framework: cisBenchCIS, Level: 1, Section: cisCatNetwork,
			Description: "Ensure packet redirect sending is disabled on default interface",
			Check: func(_ models.SecurityInfo, _ models.KernelSecurityInfo) models.CISResult {
				r := ruleByID("3.2.11")
				return checkSysctl(r, "/proc/sys/net/ipv4/conf/default/send_redirects", "0",
					"net.ipv4.conf.default.send_redirects is 1 — new interfaces will send ICMP redirects",
					"sysctl -w net.ipv4.conf.default.send_redirects=0 && echo 'net.ipv4.conf.default.send_redirects=0' >> /etc/sysctl.d/99-cis.conf")
			}},

		{ID: "3.2.12", Framework: cisBenchCIS, Level: 1, Section: cisCatNetwork,
			Description: "Ensure source routed packets are not accepted on default interface",
			Check: func(_ models.SecurityInfo, _ models.KernelSecurityInfo) models.CISResult {
				r := ruleByID("3.2.12")
				return checkSysctl(r, "/proc/sys/net/ipv4/conf/default/accept_source_route", "0",
					"net.ipv4.conf.default.accept_source_route is 1 — new interfaces will accept source-routed packets",
					"sysctl -w net.ipv4.conf.default.accept_source_route=0 && echo 'net.ipv4.conf.default.accept_source_route=0' >> /etc/sysctl.d/99-cis.conf")
			}},

		{ID: "3.2.13", Framework: cisBenchCIS, Level: 1, Section: cisCatNetwork,
			Description: "Ensure ICMP redirects are not accepted on default interface",
			Check: func(_ models.SecurityInfo, _ models.KernelSecurityInfo) models.CISResult {
				r := ruleByID("3.2.13")
				return checkSysctl(r, "/proc/sys/net/ipv4/conf/default/accept_redirects", "0",
					"net.ipv4.conf.default.accept_redirects is 1 — new interfaces will accept ICMP redirects",
					"sysctl -w net.ipv4.conf.default.accept_redirects=0 && echo 'net.ipv4.conf.default.accept_redirects=0' >> /etc/sysctl.d/99-cis.conf")
			}},

		{ID: "3.2.14", Framework: cisBenchCIS, Level: 1, Section: cisCatNetwork,
			Description: "Ensure secure ICMP redirects are not accepted on default interface",
			Check: func(_ models.SecurityInfo, _ models.KernelSecurityInfo) models.CISResult {
				r := ruleByID("3.2.14")
				return checkSysctl(r, "/proc/sys/net/ipv4/conf/default/secure_redirects", "0",
					"net.ipv4.conf.default.secure_redirects is 1 — new interfaces accept gateway ICMP redirects",
					"sysctl -w net.ipv4.conf.default.secure_redirects=0 && echo 'net.ipv4.conf.default.secure_redirects=0' >> /etc/sysctl.d/99-cis.conf")
			}},

		{ID: "3.2.15", Framework: cisBenchCIS, Level: 1, Section: cisCatNetwork,
			Description: "Ensure suspicious packets are logged on default interface (log_martians)",
			Check: func(_ models.SecurityInfo, _ models.KernelSecurityInfo) models.CISResult {
				r := ruleByID("3.2.15")
				return checkSysctl(r, "/proc/sys/net/ipv4/conf/default/log_martians", "1",
					"net.ipv4.conf.default.log_martians is 0 — new interfaces will not log martian packets",
					"sysctl -w net.ipv4.conf.default.log_martians=1 && echo 'net.ipv4.conf.default.log_martians=1' >> /etc/sysctl.d/99-cis.conf")
			}},

		{ID: "3.2.16", Framework: cisBenchCIS, Level: 1, Section: cisCatNetwork,
			Description: "Ensure Reverse Path Filtering is enabled on default interface",
			Check: func(_ models.SecurityInfo, _ models.KernelSecurityInfo) models.CISResult {
				r := ruleByID("3.2.16")
				return checkSysctl(r, "/proc/sys/net/ipv4/conf/default/rp_filter", "1",
					"net.ipv4.conf.default.rp_filter is 0 — new interfaces will not enforce reverse path filtering",
					"sysctl -w net.ipv4.conf.default.rp_filter=1 && echo 'net.ipv4.conf.default.rp_filter=1' >> /etc/sysctl.d/99-cis.conf")
			}},

		{ID: "3.2.17", Framework: cisBenchCIS, Level: 1, Section: cisCatNetwork,
			Description: "Ensure IPv6 router advertisements are not accepted on default interface",
			Check: func(_ models.SecurityInfo, _ models.KernelSecurityInfo) models.CISResult {
				r := ruleByID("3.2.17")
				return checkSysctl(r, "/proc/sys/net/ipv6/conf/default/accept_ra", "0",
					"net.ipv6.conf.default.accept_ra is not 0 — new interfaces will accept IPv6 router advertisements",
					"sysctl -w net.ipv6.conf.default.accept_ra=0 && echo 'net.ipv6.conf.default.accept_ra=0' >> /etc/sysctl.d/99-cis.conf")
			}},

		{ID: "3.2.18", Framework: cisBenchCIS, Level: 1, Section: cisCatNetwork,
			Description: "Ensure IPv6 redirects are not accepted on default interface",
			Check: func(_ models.SecurityInfo, _ models.KernelSecurityInfo) models.CISResult {
				r := ruleByID("3.2.18")
				return checkSysctl(r, "/proc/sys/net/ipv6/conf/default/accept_redirects", "0",
					"net.ipv6.conf.default.accept_redirects is not 0 — new interfaces will accept IPv6 ICMP redirects",
					"sysctl -w net.ipv6.conf.default.accept_redirects=0 && echo 'net.ipv6.conf.default.accept_redirects=0' >> /etc/sysctl.d/99-cis.conf")
			}},
		{ID: "3.2.22", Framework: cisBenchCIS, Level: 2, Section: cisCatNetwork,
			Description: "Ensure TCP timestamps are disabled (net.ipv4.tcp_timestamps = 0)",
			Check: func(_ models.SecurityInfo, _ models.KernelSecurityInfo) models.CISResult {
				r := ruleByID("3.2.22")
				return checkSysctl(r, "/proc/sys/net/ipv4/tcp_timestamps", "0",
					"net.ipv4.tcp_timestamps is not 0 — TCP timestamps may allow remote clock fingerprinting and sequence number inference",
					"sysctl -w net.ipv4.tcp_timestamps=0 && echo 'net.ipv4.tcp_timestamps=0' >> /etc/sysctl.d/99-cis.conf")
			}},
		{ID: "3.2.23", Framework: cisBenchCIS, Level: 1, Section: cisCatNetwork,
			Description: "Ensure ARP requests are filtered on non-target interfaces (net.ipv4.conf.all.arp_ignore = 1)",
			Check: func(_ models.SecurityInfo, _ models.KernelSecurityInfo) models.CISResult {
				r := ruleByID("3.2.23")
				return checkSysctl(r, "/proc/sys/net/ipv4/conf/all/arp_ignore", "1",
					"net.ipv4.conf.all.arp_ignore is not 1 — host replies to ARP requests for IPs bound to other interfaces (ARP spoofing risk)",
					"sysctl -w net.ipv4.conf.all.arp_ignore=1 && echo 'net.ipv4.conf.all.arp_ignore=1' >> /etc/sysctl.d/99-cis.conf")
			}},
		{ID: "3.2.24", Framework: cisBenchCIS, Level: 1, Section: cisCatNetwork,
			Description: "Ensure ARP announcements use the best local address (net.ipv4.conf.all.arp_announce = 2)",
			Check: func(_ models.SecurityInfo, _ models.KernelSecurityInfo) models.CISResult {
				r := ruleByID("3.2.24")
				return checkSysctl(r, "/proc/sys/net/ipv4/conf/all/arp_announce", "2",
					"net.ipv4.conf.all.arp_announce is not 2 — ARP packets may advertise unroutable source IPs, confusing neighbours",
					"sysctl -w net.ipv4.conf.all.arp_announce=2 && echo 'net.ipv4.conf.all.arp_announce=2' >> /etc/sysctl.d/99-cis.conf")
			}},
		{ID: "3.2.25", Framework: cisBenchCIS, Level: 1, Section: cisCatNetwork,
			Description: "Ensure ARP requests are filtered on non-target default interfaces (net.ipv4.conf.default.arp_ignore = 1)",
			Check: func(_ models.SecurityInfo, _ models.KernelSecurityInfo) models.CISResult {
				r := ruleByID("3.2.25")
				return checkSysctl(r, "/proc/sys/net/ipv4/conf/default/arp_ignore", "1",
					"net.ipv4.conf.default.arp_ignore is not 1 — new interfaces will reply to ARP for IPs bound to other interfaces",
					"sysctl -w net.ipv4.conf.default.arp_ignore=1 && echo 'net.ipv4.conf.default.arp_ignore=1' >> /etc/sysctl.d/99-cis.conf")
			}},
		{ID: "3.2.26", Framework: cisBenchCIS, Level: 1, Section: cisCatNetwork,
			Description: "Ensure ARP announcements use best local address on default interfaces (net.ipv4.conf.default.arp_announce = 2)",
			Check: func(_ models.SecurityInfo, _ models.KernelSecurityInfo) models.CISResult {
				r := ruleByID("3.2.26")
				return checkSysctl(r, "/proc/sys/net/ipv4/conf/default/arp_announce", "2",
					"net.ipv4.conf.default.arp_announce is not 2 — new interfaces may advertise unroutable source IPs in ARP",
					"sysctl -w net.ipv4.conf.default.arp_announce=2 && echo 'net.ipv4.conf.default.arp_announce=2' >> /etc/sysctl.d/99-cis.conf")
			}},
		{ID: "3.2.27", Framework: cisBenchCIS, Level: 1, Section: cisCatNetwork,
			Description: "Ensure TIME_WAIT assassination is prevented (net.ipv4.tcp_rfc1337 = 1)",
			Check: func(_ models.SecurityInfo, _ models.KernelSecurityInfo) models.CISResult {
				r := ruleByID("3.2.27")
				return checkSysctl(r, "/proc/sys/net/ipv4/tcp_rfc1337", "1",
					"net.ipv4.tcp_rfc1337 is not 1 — RST packets from TIME_WAIT connections can abort established sessions",
					"sysctl -w net.ipv4.tcp_rfc1337=1 && echo 'net.ipv4.tcp_rfc1337=1' >> /etc/sysctl.d/99-cis.conf")
			}},
		{ID: "3.2.28", Framework: cisBenchCIS, Level: 1, Section: cisCatNetwork,
			Description: "Ensure loopback routing is disabled on all interfaces (net.ipv4.conf.all.route_localnet = 0)",
			Check: func(_ models.SecurityInfo, _ models.KernelSecurityInfo) models.CISResult {
				r := ruleByID("3.2.28")
				return checkSysctl(r, "/proc/sys/net/ipv4/conf/all/route_localnet", "0",
					"net.ipv4.conf.all.route_localnet is not 0 — loopback addresses can be routed via non-loopback interfaces (SSRF risk)",
					"sysctl -w net.ipv4.conf.all.route_localnet=0 && echo 'net.ipv4.conf.all.route_localnet=0' >> /etc/sysctl.d/99-cis.conf")
			}},
		{ID: "3.2.29", Framework: cisBenchCIS, Level: 1, Section: cisCatNetwork,
			Description: "Ensure loopback routing is disabled on default interface (net.ipv4.conf.default.route_localnet = 0)",
			Check: func(_ models.SecurityInfo, _ models.KernelSecurityInfo) models.CISResult {
				r := ruleByID("3.2.29")
				return checkSysctl(r, "/proc/sys/net/ipv4/conf/default/route_localnet", "0",
					"net.ipv4.conf.default.route_localnet is not 0 — new interfaces will route loopback addresses",
					"sysctl -w net.ipv4.conf.default.route_localnet=0 && echo 'net.ipv4.conf.default.route_localnet=0' >> /etc/sysctl.d/99-cis.conf")
			}},
		{ID: "3.2.30", Framework: cisBenchCIS, Level: 1, Section: cisCatNetwork,
			Description: "Ensure proxy ARP is disabled on all interfaces (net.ipv4.conf.all.proxy_arp = 0)",
			Check: func(_ models.SecurityInfo, _ models.KernelSecurityInfo) models.CISResult {
				r := ruleByID("3.2.30")
				return checkSysctl(r, "/proc/sys/net/ipv4/conf/all/proxy_arp", "0",
					"net.ipv4.conf.all.proxy_arp is not 0 — host answers ARP requests on behalf of other hosts (ARP poisoning risk)",
					"sysctl -w net.ipv4.conf.all.proxy_arp=0 && echo 'net.ipv4.conf.all.proxy_arp=0' >> /etc/sysctl.d/99-cis.conf")
			}},
		{ID: "3.2.31", Framework: cisBenchCIS, Level: 1, Section: cisCatNetwork,
			Description: "Ensure proxy ARP is disabled on default interface (net.ipv4.conf.default.proxy_arp = 0)",
			Check: func(_ models.SecurityInfo, _ models.KernelSecurityInfo) models.CISResult {
				r := ruleByID("3.2.31")
				return checkSysctl(r, "/proc/sys/net/ipv4/conf/default/proxy_arp", "0",
					"net.ipv4.conf.default.proxy_arp is not 0 — new interfaces will answer ARP on behalf of other hosts",
					"sysctl -w net.ipv4.conf.default.proxy_arp=0 && echo 'net.ipv4.conf.default.proxy_arp=0' >> /etc/sysctl.d/99-cis.conf")
			}},
		{ID: "3.2.32", Framework: cisBenchCIS, Level: 1, Section: cisCatNetwork,
			Description: "Ensure source routed packets are not accepted on default interface (net.ipv4.conf.default.accept_source_route = 0)",
			Check: func(_ models.SecurityInfo, _ models.KernelSecurityInfo) models.CISResult {
				r := ruleByID("3.2.32")
				return checkSysctl(r, "/proc/sys/net/ipv4/conf/default/accept_source_route", "0",
					"net.ipv4.conf.default.accept_source_route is not 0 — source routing accepted on new interfaces",
					"sysctl -w net.ipv4.conf.default.accept_source_route=0 && echo 'net.ipv4.conf.default.accept_source_route=0' >> /etc/sysctl.d/99-cis.conf")
			}},
		{ID: "3.2.33", Framework: cisBenchCIS, Level: 1, Section: cisCatNetwork,
			Description: "Ensure ICMP redirects are not accepted on default interface (net.ipv4.conf.default.accept_redirects = 0)",
			Check: func(_ models.SecurityInfo, _ models.KernelSecurityInfo) models.CISResult {
				r := ruleByID("3.2.33")
				return checkSysctl(r, "/proc/sys/net/ipv4/conf/default/accept_redirects", "0",
					"net.ipv4.conf.default.accept_redirects is not 0 — ICMP redirects accepted on new interfaces",
					"sysctl -w net.ipv4.conf.default.accept_redirects=0 && echo 'net.ipv4.conf.default.accept_redirects=0' >> /etc/sysctl.d/99-cis.conf")
			}},
		{ID: "3.2.34", Framework: cisBenchCIS, Level: 1, Section: cisCatNetwork,
			Description: "Ensure secure ICMP redirects are not accepted on default interface (net.ipv4.conf.default.secure_redirects = 0)",
			Check: func(_ models.SecurityInfo, _ models.KernelSecurityInfo) models.CISResult {
				r := ruleByID("3.2.34")
				return checkSysctl(r, "/proc/sys/net/ipv4/conf/default/secure_redirects", "0",
					"net.ipv4.conf.default.secure_redirects is not 0 — gateway ICMP redirects accepted on new interfaces",
					"sysctl -w net.ipv4.conf.default.secure_redirects=0 && echo 'net.ipv4.conf.default.secure_redirects=0' >> /etc/sysctl.d/99-cis.conf")
			}},
		{ID: "3.2.35", Framework: cisBenchCIS, Level: 1, Section: cisCatNetwork,
			Description: "Ensure suspicious packets are logged on default interface (net.ipv4.conf.default.log_martians = 1)",
			Check: func(_ models.SecurityInfo, _ models.KernelSecurityInfo) models.CISResult {
				r := ruleByID("3.2.35")
				return checkSysctl(r, "/proc/sys/net/ipv4/conf/default/log_martians", "1",
					"net.ipv4.conf.default.log_martians is not 1 — martian packets not logged on new interfaces",
					"sysctl -w net.ipv4.conf.default.log_martians=1 && echo 'net.ipv4.conf.default.log_martians=1' >> /etc/sysctl.d/99-cis.conf")
			}},
		{ID: "3.2.36", Framework: cisBenchCIS, Level: 1, Section: cisCatNetwork,
			Description: "Ensure IPv6 router advertisements are not accepted on default interface (net.ipv6.conf.default.accept_ra = 0)",
			Check: func(_ models.SecurityInfo, _ models.KernelSecurityInfo) models.CISResult {
				r := ruleByID("3.2.36")
				return checkSysctl(r, "/proc/sys/net/ipv6/conf/default/accept_ra", "0",
					"net.ipv6.conf.default.accept_ra is not 0 — new interfaces will accept IPv6 router advertisements",
					"sysctl -w net.ipv6.conf.default.accept_ra=0 && echo 'net.ipv6.conf.default.accept_ra=0' >> /etc/sysctl.d/99-cis.conf")
			}},
		{ID: "3.2.37", Framework: cisBenchCIS, Level: 1, Section: cisCatNetwork,
			Description: "Ensure IPv6 redirects are not accepted on default interface (net.ipv6.conf.default.accept_redirects = 0)",
			Check: func(_ models.SecurityInfo, _ models.KernelSecurityInfo) models.CISResult {
				r := ruleByID("3.2.37")
				return checkSysctl(r, "/proc/sys/net/ipv6/conf/default/accept_redirects", "0",
					"net.ipv6.conf.default.accept_redirects is not 0 — new interfaces will accept IPv6 ICMP redirects",
					"sysctl -w net.ipv6.conf.default.accept_redirects=0 && echo 'net.ipv6.conf.default.accept_redirects=0' >> /etc/sysctl.d/99-cis.conf")
			}},
		{ID: "3.2.38", Framework: cisBenchCIS, Level: 1, Section: cisCatNetwork,
			Description: "Ensure IPv6 source routing is not accepted (net.ipv6.conf.all.accept_source_route = 0)",
			Check: func(_ models.SecurityInfo, _ models.KernelSecurityInfo) models.CISResult {
				r := ruleByID("3.2.38")
				return checkSysctl(r, "/proc/sys/net/ipv6/conf/all/accept_source_route", "0",
					"net.ipv6.conf.all.accept_source_route is not 0 — IPv6 source-routed packets accepted",
					"sysctl -w net.ipv6.conf.all.accept_source_route=0 && echo 'net.ipv6.conf.all.accept_source_route=0' >> /etc/sysctl.d/99-cis.conf")
			}},
		{ID: "3.2.39", Framework: cisBenchCIS, Level: 1, Section: cisCatNetwork,
			Description: "Ensure IPv6 source routing is not accepted on default interface (net.ipv6.conf.default.accept_source_route = 0)",
			Check: func(_ models.SecurityInfo, _ models.KernelSecurityInfo) models.CISResult {
				r := ruleByID("3.2.39")
				return checkSysctl(r, "/proc/sys/net/ipv6/conf/default/accept_source_route", "0",
					"net.ipv6.conf.default.accept_source_route is not 0 — new interfaces will accept IPv6 source-routed packets",
					"sysctl -w net.ipv6.conf.default.accept_source_route=0 && echo 'net.ipv6.conf.default.accept_source_route=0' >> /etc/sysctl.d/99-cis.conf")
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

		{ID: "3.4.5", Framework: cisBenchCIS, Level: 2, Section: cisCatNetwork,
			Description: "Ensure bluetooth is disabled",
			Check: func(_ models.SecurityInfo, _ models.KernelSecurityInfo) models.CISResult {
				return checkModuleDisabled(ruleByID("3.4.5"), "bluetooth",
					"echo 'install bluetooth /bin/true' > /etc/modprobe.d/bluetooth.conf && systemctl disable bluetooth")
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

		{ID: "3.5.1.1", Framework: cisBenchCIS, Level: 1, Section: cisCatNetwork,
			Description: "Ensure ufw is installed",
			Check: func(_ models.SecurityInfo, _ models.KernelSecurityInfo) models.CISResult {
				r := ruleByID("3.5.1.1")
				if _, err := os.Stat(debianVersionPath); err != nil {
					return skipr(r, "ufw rule applies to Debian/Ubuntu systems only")
				}
				for _, p := range ufwBinPaths {
					if _, err := os.Stat(p); err == nil {
						return pass(r)
					}
				}
				return failr(r, "ufw binary not found", firewallInstallCmd("apt"))
			}},

		{ID: "3.5.1.2", Framework: cisBenchCIS, Level: 1, Section: cisCatNetwork,
			Description: "Ensure iptables-persistent is not installed with ufw",
			Check: func(_ models.SecurityInfo, _ models.KernelSecurityInfo) models.CISResult {
				r := ruleByID("3.5.1.2")
				if _, err := os.Stat(debianVersionPath); err != nil {
					return skipr(r, cisSkipDebianOnly)
				}
				for _, p := range netfilterPersistentPaths {
					if _, err := os.Stat(p); err == nil {
						return failr(r,
							"iptables-persistent (netfilter-persistent) is installed — conflicts with ufw",
							iptablesPersistentRemoveCmd("apt"))
					}
				}
				return pass(r)
			}},

		{ID: "3.5.1.3", Framework: cisBenchCIS, Level: 1, Section: cisCatNetwork,
			Description: "Ensure ufw service is enabled",
			Check: func(_ models.SecurityInfo, _ models.KernelSecurityInfo) models.CISResult {
				r := ruleByID("3.5.1.3")
				ufwPresent := false
				for _, p := range ufwBinPaths {
					if _, err := os.Stat(p); err == nil {
						ufwPresent = true
						break
					}
				}
				if !ufwPresent {
					return skipr(r, "ufw not installed")
				}
				for _, p := range ufwWantsPaths {
					if _, err := os.Stat(p); err == nil {
						return pass(r)
					}
				}
				return failr(r,
					"ufw service is not enabled",
					"ufw enable && systemctl enable ufw")
			}},

		{ID: "3.5.1.4", Framework: cisBenchCIS, Level: 1, Section: cisCatNetwork,
			Description: "Ensure ufw loopback traffic is configured",
			Check: func(_ models.SecurityInfo, _ models.KernelSecurityInfo) models.CISResult {
				r := ruleByID("3.5.1.4")
				data, err := os.ReadFile(ufwBeforeRulesPath) // #nosec G304 -- package-level var
				if err != nil {
					return skipr(r, "ufw not configured — /etc/ufw/before.rules not found")
				}
				content := strings.ToLower(string(data))
				hasInput := strings.Contains(content, "-i lo -j accept")
				hasOutput := strings.Contains(content, "-o lo -j accept")
				hasDeny127 := strings.Contains(content, "127.0.0.0/8") &&
					(strings.Contains(content, "-j drop") || strings.Contains(content, "-j deny"))
				if !hasInput || !hasOutput || !hasDeny127 {
					var missing []string
					if !hasInput {
						missing = append(missing, "loopback input ACCEPT rule")
					}
					if !hasOutput {
						missing = append(missing, "loopback output ACCEPT rule")
					}
					if !hasDeny127 {
						missing = append(missing, "127.0.0.0/8 deny rule")
					}
					return failr(r,
						fmt.Sprintf("missing loopback rules in before.rules: %s", strings.Join(missing, ", ")),
						"restore default loopback rules in /etc/ufw/before.rules or reinstall ufw")
				}
				data6, err := os.ReadFile(ufwBefore6RulesPath) // #nosec G304 -- package-level var
				if err == nil {
					c6 := strings.ToLower(string(data6))
					hasIn6 := strings.Contains(c6, "-i lo -j accept")
					hasOut6 := strings.Contains(c6, "-o lo -j accept")
					hasDeny6 := strings.Contains(c6, "::1") &&
						(strings.Contains(c6, "-j drop") || strings.Contains(c6, "-j deny"))
					if !hasIn6 || !hasOut6 || !hasDeny6 {
						var missing []string
						if !hasIn6 {
							missing = append(missing, "IPv6 loopback input ACCEPT")
						}
						if !hasOut6 {
							missing = append(missing, "IPv6 loopback output ACCEPT")
						}
						if !hasDeny6 {
							missing = append(missing, "::1 deny rule")
						}
						return failr(r,
							fmt.Sprintf("missing IPv6 loopback rules in before6.rules: %s", strings.Join(missing, ", ")),
							"restore default IPv6 loopback rules in /etc/ufw/before6.rules")
					}
				}
				return pass(r)
			}},

		{ID: "3.5.1.5", Framework: cisBenchCIS, Level: 2, Section: cisCatNetwork,
			Description: "Ensure ufw outbound connections are configured",
			Check: func(_ models.SecurityInfo, _ models.KernelSecurityInfo) models.CISResult {
				r := ruleByID("3.5.1.5")
				data, err := os.ReadFile(ufwDefaultPath) // #nosec G304 -- package-level var
				if err != nil {
					return skipr(r, "ufw not configured — /etc/default/ufw not found")
				}
				for line := range strings.SplitSeq(string(data), "\n") {
					trimmed := strings.TrimSpace(line)
					if trimmed == "" || strings.HasPrefix(trimmed, "#") {
						continue
					}
					rest, ok := strings.CutPrefix(trimmed, "DEFAULT_OUTPUT_POLICY=")
					if !ok {
						continue
					}
					val := strings.Trim(rest, "\"'")
					if strings.EqualFold(val, "ALLOW") {
						return pass(r)
					}
					break
				}
				data2, err := os.ReadFile(ufwUserRulesPath) // #nosec G304 -- package-level var
				if err != nil {
					return failr(r,
						"ufw output policy is not ALLOW and user.rules is unreadable",
						"configure outbound rules: set DEFAULT_OUTPUT_POLICY=ALLOW in /etc/default/ufw")
				}
				content := strings.ToLower(string(data2))
				if strings.Contains(content, "-a ufw-user-output -j accept") ||
					strings.Contains(content, "-a ufw-user-output -j return") ||
					strings.Contains(content, "allow out") {
					return pass(r)
				}
				return failr(r,
					"ufw DEFAULT_OUTPUT_POLICY is not ALLOW and no explicit allow-out rules found",
					"set DEFAULT_OUTPUT_POLICY=ALLOW in /etc/default/ufw or add explicit allow-out rules")
			}},

		{ID: "3.5.1.6", Framework: cisBenchCIS, Level: 1, Section: cisCatNetwork,
			Description: "Ensure ufw firewall rules exist for all open ports",
			Check: func(sec models.SecurityInfo, _ models.KernelSecurityInfo) models.CISResult {
				r := ruleByID("3.5.1.6")
				ufwPresent := false
				for _, p := range ufwBinPaths {
					if _, err := os.Stat(p); err == nil {
						ufwPresent = true
						break
					}
				}
				if !ufwPresent {
					return skipr(r, "ufw not installed")
				}
				data, err := os.ReadFile(ufwUserRulesPath) //nolint:gosec // package-level var
				if err != nil {
					return skipr(r, "ufw user.rules not readable (run as root for full coverage)")
				}
				// Parse inbound ACCEPT ports from the ufw-user-input chain.
				allowedPorts := make(map[int]bool)
				hasRangeRule := false
				for line := range strings.SplitSeq(string(data), "\n") {
					line = strings.TrimSpace(line)
					if !strings.Contains(line, "ufw-user-input") || !strings.HasSuffix(line, "-j ACCEPT") {
						continue
					}
					// --dports N,M,P (multiport)
					if _, after, ok2 := strings.Cut(line, "--dports "); ok2 {
						portSpec, _, _ := strings.Cut(after, " ")
						for p := range strings.SplitSeq(portSpec, ",") {
							if n, err2 := strconv.Atoi(strings.TrimSpace(p)); err2 == nil {
								allowedPorts[n] = true
							}
						}
						continue
					}
					// --dport N or --dport N:M (range)
					if _, after, ok2 := strings.Cut(line, "--dport "); ok2 {
						portSpec, _, _ := strings.Cut(after, " ")
						if strings.Contains(portSpec, ":") {
							hasRangeRule = true
						} else if n, err2 := strconv.Atoi(strings.TrimSpace(portSpec)); err2 == nil {
							allowedPorts[n] = true
						}
					}
				}
				if len(sec.ListeningPorts) == 0 {
					return pass(r)
				}
				var uncovered []string
				for _, pe := range sec.ListeningPorts {
					if pe.Port <= 0 {
						continue
					}
					if allowedPorts[pe.Port] || hasRangeRule {
						continue
					}
					uncovered = append(uncovered,
						fmt.Sprintf("%d/%s(%s)", pe.Port, pe.Protocol, pe.Process))
				}
				if len(uncovered) == 0 {
					return pass(r)
				}
				return failr(r,
					fmt.Sprintf("listening ports with no explicit ufw allow rule: %s",
						strings.Join(uncovered, ", ")),
					"add ufw rules: ufw allow <port>/<proto> for each service")
			}},

		{ID: "3.5.1.7", Framework: cisBenchCIS, Level: 1, Section: cisCatNetwork,
			Description: "Ensure ufw default deny firewall policy",
			Check: func(_ models.SecurityInfo, _ models.KernelSecurityInfo) models.CISResult {
				r := ruleByID("3.5.1.7")
				data, err := os.ReadFile(ufwDefaultPath) // #nosec G304 -- package-level var
				if err != nil {
					return skipr(r, "ufw not configured or /etc/default/ufw unreadable")
				}
				var inputPolicy, forwardPolicy string
				for line := range strings.SplitSeq(string(data), "\n") {
					trimmed := strings.TrimSpace(line)
					if trimmed == "" || strings.HasPrefix(trimmed, "#") {
						continue
					}
					if rest, ok := strings.CutPrefix(trimmed, "DEFAULT_INPUT_POLICY="); ok {
						inputPolicy = strings.Trim(rest, "\"'")
					}
					if rest, ok := strings.CutPrefix(trimmed, "DEFAULT_FORWARD_POLICY="); ok {
						forwardPolicy = strings.Trim(rest, "\"'")
					}
				}
				if inputPolicy == "" && forwardPolicy == "" {
					return skipr(r, "no DEFAULT_INPUT_POLICY or DEFAULT_FORWARD_POLICY found in /etc/default/ufw")
				}
				if strings.EqualFold(inputPolicy, "ACCEPT") {
					return failr(r,
						fmt.Sprintf("DEFAULT_INPUT_POLICY is %q — incoming traffic allowed by default", inputPolicy),
						"set DEFAULT_INPUT_POLICY=\"DROP\" in /etc/default/ufw and run: ufw reload")
				}
				if strings.EqualFold(forwardPolicy, "ACCEPT") {
					return failr(r,
						fmt.Sprintf("DEFAULT_FORWARD_POLICY is %q — forwarding allowed by default", forwardPolicy),
						"set DEFAULT_FORWARD_POLICY=\"DROP\" in /etc/default/ufw and run: ufw reload")
				}
				return pass(r)
			}},

		// ── 3.6 Wireless Interfaces ──────────────────────────────────────────

		{ID: "3.6.1", Framework: cisBenchCIS, Level: 1, Section: cisCatNetwork,
			Description: "Ensure wireless interfaces are disabled",
			Check: func(_ models.SecurityInfo, _ models.KernelSecurityInfo) models.CISResult {
				r := ruleByID("3.6.1")
				entries, err := os.ReadDir(sysClassNetPath) //nolint:gosec // package-level var
				if err != nil {
					return skipr(r, "/sys/class/net not readable")
				}
				var up []string
				for _, e := range entries {
					wirelessDir := filepath.Join(sysClassNetPath, e.Name(), "wireless")
					if _, err := os.Stat(wirelessDir); err != nil {
						continue
					}
					flagsPath := filepath.Join(sysClassNetPath, e.Name(), "flags")
					flagsData, err := os.ReadFile(flagsPath) // #nosec G304 -- sysfs path from ReadDir
					if err != nil {
						up = append(up, e.Name())
						continue
					}
					flagStr := strings.TrimSpace(string(flagsData))
					flags, err := strconv.ParseInt(strings.TrimPrefix(flagStr, "0x"), 16, 64)
					if err != nil || flags&0x1 != 0 {
						up = append(up, e.Name())
					}
				}
				if len(up) > 0 {
					return failr(r,
						fmt.Sprintf("wireless interface(s) are active: %s", strings.Join(up, ", ")),
						"disable wireless: ip link set <iface> down && rfkill block all")
				}
				return pass(r)
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

		{ID: "4.1.1.1", Framework: cisBenchCIS, Level: 2, Section: "Audit",
			Description: "Ensure audit log storage size is configured",
			Check: func(sec models.SecurityInfo, _ models.KernelSecurityInfo) models.CISResult {
				r := ruleByID("4.1.1.1")
				if sec.AuditRules == -1 {
					return skipr(r, cisSkipAuditdUnavailable)
				}
				data, err := os.ReadFile(auditdConfPath) // #nosec G304 -- package-level var
				if err != nil {
					return skipr(r, cisSkipAuditdConfUnreadable)
				}
				for line := range strings.SplitSeq(string(data), "\n") {
					parts := strings.SplitN(strings.TrimSpace(line), "=", 2)
					if len(parts) != 2 {
						continue
					}
					if strings.TrimSpace(strings.ToLower(parts[0])) != "max_log_file" {
						continue
					}
					val := strings.TrimSpace(parts[1])
					n, err := strconv.Atoi(val)
					if err != nil {
						return skipr(r, fmt.Sprintf("max_log_file value %q not parseable", val))
					}
					if n == 0 {
						return failr(r, "max_log_file = 0 — audit log size limit not configured",
							"set max_log_file = 8 (or site-defined value) in /etc/audit/auditd.conf")
					}
					return pass(r)
				}
				return failr(r, "max_log_file not set in auditd.conf",
					"add max_log_file = 8 to /etc/audit/auditd.conf")
			}},

		{ID: "4.1.1.2", Framework: cisBenchCIS, Level: 2, Section: "Audit",
			Description: "Ensure audit logs are not automatically deleted",
			Check: func(sec models.SecurityInfo, _ models.KernelSecurityInfo) models.CISResult {
				r := ruleByID("4.1.1.2")
				if sec.AuditRules == -1 {
					return skipr(r, cisSkipAuditdUnavailable)
				}
				data, err := os.ReadFile(auditdConfPath) // #nosec G304 -- package-level var
				if err != nil {
					return skipr(r, cisSkipAuditdConfUnreadable)
				}
				for line := range strings.SplitSeq(string(data), "\n") {
					parts := strings.SplitN(strings.TrimSpace(line), "=", 2)
					if len(parts) != 2 {
						continue
					}
					if strings.TrimSpace(strings.ToLower(parts[0])) != "max_log_file_action" {
						continue
					}
					val := strings.ToLower(strings.TrimSpace(parts[1]))
					if val == "rotate" || val == "ignore" {
						return failr(r,
							fmt.Sprintf("max_log_file_action = %q — old audit logs may be silently discarded", val),
							"set max_log_file_action = keep_logs in /etc/audit/auditd.conf")
					}
					return pass(r)
				}
				return failr(r, "max_log_file_action not set in auditd.conf",
					"add max_log_file_action = keep_logs to /etc/audit/auditd.conf")
			}},

		{ID: "4.1.1.3", Framework: cisBenchCIS, Level: 2, Section: "Audit",
			Description: "Ensure system is disabled when audit logs are full",
			Check: func(sec models.SecurityInfo, _ models.KernelSecurityInfo) models.CISResult {
				r := ruleByID("4.1.1.3")
				if sec.AuditRules == -1 {
					return skipr(r, cisSkipAuditdUnavailable)
				}
				data, err := os.ReadFile(auditdConfPath) // #nosec G304 -- package-level var
				if err != nil {
					return skipr(r, cisSkipAuditdConfUnreadable)
				}
				spaceLeft, adminSpaceLeft := "", ""
				for line := range strings.SplitSeq(string(data), "\n") {
					parts := strings.SplitN(strings.TrimSpace(line), "=", 2)
					if len(parts) != 2 {
						continue
					}
					key := strings.TrimSpace(strings.ToLower(parts[0]))
					val := strings.ToLower(strings.TrimSpace(parts[1]))
					switch key {
					case "space_left_action":
						spaceLeft = val
					case "admin_space_left_action":
						adminSpaceLeft = val
					}
				}
				safeActions := map[string]bool{"halt": true, "single": true, "email": true, "exec": true}
				if !safeActions[spaceLeft] {
					return failr(r,
						fmt.Sprintf("space_left_action = %q — system won't halt/notify on low disk", spaceLeft),
						"set space_left_action = email in /etc/audit/auditd.conf")
				}
				if adminSpaceLeft != "halt" && adminSpaceLeft != "single" {
					return failr(r,
						fmt.Sprintf("admin_space_left_action = %q — system won't halt when disk is critically full", adminSpaceLeft),
						"set admin_space_left_action = halt in /etc/audit/auditd.conf")
				}
				return pass(r)
			}},

		{ID: "4.1.1.4", Framework: cisBenchCIS, Level: 2, Section: "Audit",
			Description: "Ensure audit_backlog_limit is sufficient",
			Check: func(sec models.SecurityInfo, _ models.KernelSecurityInfo) models.CISResult {
				r := ruleByID("4.1.1.4")
				if sec.AuditRules == -1 {
					return skipr(r, cisSkipAuditdUnavailable)
				}
				data, err := os.ReadFile(procCmdlinePath) // #nosec G304 -- package-level var
				if err != nil {
					return skipr(r, "/proc/cmdline not readable")
				}
				for param := range strings.FieldsSeq(strings.TrimSpace(string(data))) {
					rest, ok := strings.CutPrefix(param, "audit_backlog_limit=")
					if !ok {
						continue
					}
					n, parseErr := strconv.ParseInt(rest, 10, 64)
					if parseErr != nil {
						return failr(r, fmt.Sprintf("audit_backlog_limit=%q is not a valid integer", rest),
							cisFixAuditBacklogGrub)
					}
					if n < 8192 {
						return failr(r, fmt.Sprintf("audit_backlog_limit=%d is below the CIS minimum of 8192", n),
							cisFixAuditBacklogGrub)
					}
					return pass(r)
				}
				return failr(r, "audit_backlog_limit not set in kernel command line (default 64 is too low)",
					cisFixAuditBacklogGrub)
			}},

		{ID: "4.1.1.5", Framework: cisBenchCIS, Level: 2, Section: "Audit",
			Description: "Ensure auditing for processes prior to auditd is enabled (audit=1 in kernel cmdline)",
			Check: func(sec models.SecurityInfo, _ models.KernelSecurityInfo) models.CISResult {
				r := ruleByID("4.1.1.5")
				if sec.AuditRules == -1 {
					return skipr(r, cisSkipAuditdUnavailable)
				}
				data, err := os.ReadFile(procCmdlinePath) // #nosec G304 -- package-level var
				if err != nil {
					return skipr(r, "/proc/cmdline not readable")
				}
				for param := range strings.FieldsSeq(strings.TrimSpace(string(data))) {
					if param == "audit=1" {
						return pass(r)
					}
					if param == "audit=0" {
						return failr(r, "audit=0 in kernel cmdline — auditing explicitly disabled for early-boot processes",
							"remove audit=0 and add audit=1 to GRUB_CMDLINE_LINUX in /etc/default/grub, then run update-grub")
					}
				}
				return failr(r, "audit=1 not in kernel cmdline — processes starting before auditd may not be audited",
					"add 'audit=1' to GRUB_CMDLINE_LINUX in /etc/default/grub and run update-grub")
			}},

		{ID: "4.1.2", StigID: "V-238361",
			StigDescription: "The auditd service must be running and enabled", Framework: cisBenchBOTH, Level: 1, Section: "Audit",
			Description: "Ensure auditd has rules configured",
			Check: func(sec models.SecurityInfo, _ models.KernelSecurityInfo) models.CISResult {
				r := ruleByID("4.1.2")
				if sec.AuditRules == -1 {
					return skipr(r, cisSkipAuditdUnavailable)
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

		{ID: "4.2.2", Framework: cisBenchCIS, Level: 1, Section: "Audit",
			Description: "Ensure journald is configured to send logs to rsyslog",
			Check: func(_ models.SecurityInfo, _ models.KernelSecurityInfo) models.CISResult {
				r := ruleByID("4.2.2")
				var lines []string
				if data, err := os.ReadFile(journaldConfPath); err == nil { //nolint:gosec // package-level var
					for line := range strings.SplitSeq(string(data), "\n") {
						lines = append(lines, line)
					}
				}
				if entries, err := os.ReadDir(journaldConfDPath); err == nil { //nolint:gosec // package-level var
					for _, e := range entries {
						if e.IsDir() || !strings.HasSuffix(e.Name(), ".conf") {
							continue
						}
						data, err := os.ReadFile(filepath.Join(journaldConfDPath, e.Name())) //nolint:gosec
						if err != nil {
							continue
						}
						for line := range strings.SplitSeq(string(data), "\n") {
							lines = append(lines, line)
						}
					}
				}
				if len(lines) == 0 {
					return skipr(r, cisSkipJournaldNotFound)
				}
				for _, line := range lines {
					line = strings.TrimSpace(line)
					if strings.HasPrefix(line, "#") || line == "" {
						continue
					}
					if strings.EqualFold(line, "ForwardToSyslog=yes") {
						return pass(r)
					}
				}
				return failr(r, "ForwardToSyslog=yes not set in journald configuration",
					"add 'ForwardToSyslog=yes' to /etc/systemd/journald.conf")
			}},

		{ID: "4.2.2.2", Framework: cisBenchCIS, Level: 1, Section: "Audit",
			Description: "Ensure journald is configured to compress large log files",
			Check: func(_ models.SecurityInfo, _ models.KernelSecurityInfo) models.CISResult {
				r := ruleByID("4.2.2.2")
				hasCompress, anyConfig := false, false
				checkLines := func(data []byte) {
					for line := range strings.SplitSeq(string(data), "\n") {
						line = strings.TrimSpace(line)
						if line == "" || strings.HasPrefix(line, "#") {
							continue
						}
						anyConfig = true
						if strings.EqualFold(line, "Compress=yes") {
							hasCompress = true
						}
					}
				}
				if data, err := os.ReadFile(journaldConfPath); err == nil { //nolint:gosec // package-level var
					checkLines(data)
				}
				if entries, err := os.ReadDir(journaldConfDPath); err == nil { //nolint:gosec // package-level var
					for _, e := range entries {
						if e.IsDir() || !strings.HasSuffix(e.Name(), ".conf") {
							continue
						}
						if data, err := os.ReadFile(filepath.Join(journaldConfDPath, e.Name())); err == nil { //nolint:gosec
							checkLines(data)
						}
					}
				}
				if !anyConfig {
					return skipr(r, cisSkipJournaldNotFound)
				}
				if !hasCompress {
					return failr(r, "Compress=yes not set in journald configuration",
						"add 'Compress=yes' to /etc/systemd/journald.conf")
				}
				return pass(r)
			}},

		{ID: "4.2.2.3", Framework: cisBenchCIS, Level: 1, Section: "Audit",
			Description: "Ensure journald is configured to write logfiles to persistent disk",
			Check: func(_ models.SecurityInfo, _ models.KernelSecurityInfo) models.CISResult {
				r := ruleByID("4.2.2.3")
				hasPersistent, anyConfig := false, false
				checkLines := func(data []byte) {
					for line := range strings.SplitSeq(string(data), "\n") {
						line = strings.TrimSpace(line)
						if line == "" || strings.HasPrefix(line, "#") {
							continue
						}
						anyConfig = true
						if strings.EqualFold(line, "Storage=persistent") {
							hasPersistent = true
						}
					}
				}
				if data, err := os.ReadFile(journaldConfPath); err == nil { //nolint:gosec // package-level var
					checkLines(data)
				}
				if entries, err := os.ReadDir(journaldConfDPath); err == nil { //nolint:gosec // package-level var
					for _, e := range entries {
						if e.IsDir() || !strings.HasSuffix(e.Name(), ".conf") {
							continue
						}
						if data, err := os.ReadFile(filepath.Join(journaldConfDPath, e.Name())); err == nil { //nolint:gosec
							checkLines(data)
						}
					}
				}
				if !anyConfig {
					return skipr(r, cisSkipJournaldNotFound)
				}
				if !hasPersistent {
					return failr(r, "Storage=persistent not set in journald configuration",
						"add 'Storage=persistent' to /etc/systemd/journald.conf")
				}
				return pass(r)
			}},

		{ID: "4.2.3", Framework: cisBenchCIS, Level: 2, Section: "Audit",
			Description: "Ensure rsyslog is configured to send logs to a remote log host",
			Check: func(_ models.SecurityInfo, _ models.KernelSecurityInfo) models.CISResult {
				r := ruleByID("4.2.3")
				var lines []string
				if data, err := os.ReadFile(rsyslogConfPath); err == nil { //nolint:gosec // package-level var
					for line := range strings.SplitSeq(string(data), "\n") {
						lines = append(lines, line)
					}
				}
				if entries, err := os.ReadDir(rsyslogConfDPath); err == nil { //nolint:gosec // package-level var
					for _, e := range entries {
						if e.IsDir() || !strings.HasSuffix(e.Name(), ".conf") {
							continue
						}
						data, err := os.ReadFile(filepath.Join(rsyslogConfDPath, e.Name())) //nolint:gosec
						if err != nil {
							continue
						}
						for line := range strings.SplitSeq(string(data), "\n") {
							lines = append(lines, line)
						}
					}
				}
				if len(lines) == 0 {
					return skipr(r, "rsyslog config not readable")
				}
				for _, line := range lines {
					line = strings.TrimSpace(line)
					if strings.HasPrefix(line, "#") || line == "" {
						continue
					}
					// Match @@host (TCP) or @host (UDP) forwarding, or modern omfwd action
					if strings.HasPrefix(line, "@@") || strings.HasPrefix(line, "*.* @@") ||
						strings.HasPrefix(line, "*.* @") || strings.Contains(line, `action(type="omfwd"`) {
						return pass(r)
					}
				}
				return failr(r, "no remote log host configured in rsyslog",
					"add '*.* @@loghost.example.com' or equivalent to /etc/rsyslog.d/50-remote.conf")
			}},

		{ID: "4.2.4", Framework: cisBenchCIS, Level: 1, Section: "Audit",
			Description: "Ensure rsyslog is not accepting remote messages",
			Check: func(_ models.SecurityInfo, _ models.KernelSecurityInfo) models.CISResult {
				r := ruleByID("4.2.4")
				networkMods := []string{
					"$modload imtcp", "$modload imudp", "$modload imrelp",
					`module(load="imtcp"`, `module(load="imudp"`, `module(load="imrelp"`,
					`input(type="imtcp"`, `input(type="imudp"`, `input(type="imrelp"`,
				}
				findMod := func(data []byte) string {
					for line := range strings.SplitSeq(string(data), "\n") {
						trimmed := strings.TrimSpace(line)
						if trimmed == "" || strings.HasPrefix(trimmed, "#") {
							continue
						}
						lower := strings.ToLower(trimmed)
						for _, mod := range networkMods {
							if strings.Contains(lower, mod) {
								return trimmed
							}
						}
					}
					return ""
				}
				if data, err := os.ReadFile(rsyslogConfPath); err == nil { //nolint:gosec // package-level var
					if found := findMod(data); found != "" {
						return failr(r,
							fmt.Sprintf("rsyslog loads network receiver module: %q", found),
							"comment out or remove imtcp/imudp/imrelp module load directives from /etc/rsyslog.conf")
					}
				}
				if entries, err := os.ReadDir(rsyslogConfDPath); err == nil { //nolint:gosec // package-level var
					for _, e := range entries {
						if e.IsDir() || !strings.HasSuffix(e.Name(), ".conf") {
							continue
						}
						data, rdErr := os.ReadFile(filepath.Join(rsyslogConfDPath, e.Name())) //nolint:gosec
						if rdErr != nil {
							continue
						}
						if found := findMod(data); found != "" {
							return failr(r,
								fmt.Sprintf("rsyslog config %s loads network receiver module: %q", e.Name(), found),
								"comment out or remove imtcp/imudp/imrelp load directives from /etc/rsyslog.d/")
						}
					}
				}
				return pass(r)
			}},

		{ID: "4.2.5", Framework: cisBenchCIS, Level: 2, Section: "Audit",
			Description: "Ensure rsyslog default file creation mode is configured",
			Check: func(_ models.SecurityInfo, _ models.KernelSecurityInfo) models.CISResult {
				r := ruleByID("4.2.5")
				findMode := func(data []byte) (string, bool) {
					for line := range strings.SplitSeq(string(data), "\n") {
						trimmed := strings.TrimSpace(line)
						if trimmed == "" || strings.HasPrefix(trimmed, "#") {
							continue
						}
						// Legacy directive: $FileCreateMode 0640
						if rest, ok := strings.CutPrefix(trimmed, "$FileCreateMode"); ok {
							return strings.TrimSpace(rest), true
						}
						// RainerScript: FileCreateMode="0640" inside module() or global()
						if strings.Contains(trimmed, "FileCreateMode=") {
							for field := range strings.FieldsSeq(trimmed) {
								if rest, ok := strings.CutPrefix(field, "FileCreateMode="); ok {
									return strings.Trim(rest, "\"'"), true
								}
							}
						}
					}
					return "", false
				}
				checkMode := func(modeStr string) (bool, string) {
					modeStr = strings.Trim(modeStr, "\"'")
					v, err := strconv.ParseInt(modeStr, 8, 32)
					if err != nil {
						return false, fmt.Sprintf("unrecognised $FileCreateMode value %q", modeStr)
					}
					// Mode must not exceed 0640 (no write-other, no execute-owner)
					if v&0o137 != 0 {
						return false, fmt.Sprintf("$FileCreateMode %s is more permissive than 0640", modeStr)
					}
					return true, ""
				}
				tryFile := func(data []byte) (string, bool) {
					if modeStr, found := findMode(data); found {
						return modeStr, true
					}
					return "", false
				}
				var modeStr string
				var found bool
				if data, err := os.ReadFile(rsyslogConfPath); err == nil { //nolint:gosec // package-level var
					if modeStr, found = tryFile(data); found {
						if ok, reason := checkMode(modeStr); !ok {
							return failr(r, reason,
								"set '$FileCreateMode 0640' in /etc/rsyslog.conf or a /etc/rsyslog.d/ drop-in")
						}
						return pass(r)
					}
				}
				if entries, err := os.ReadDir(rsyslogConfDPath); err == nil { //nolint:gosec // package-level var
					for _, e := range entries {
						if e.IsDir() || !strings.HasSuffix(e.Name(), ".conf") {
							continue
						}
						data, rdErr := os.ReadFile(filepath.Join(rsyslogConfDPath, e.Name())) //nolint:gosec
						if rdErr != nil {
							continue
						}
						if modeStr, found = tryFile(data); found {
							if ok, reason := checkMode(modeStr); !ok {
								return failr(r, reason,
									"set '$FileCreateMode 0640' in /etc/rsyslog.conf or a /etc/rsyslog.d/ drop-in")
							}
							return pass(r)
						}
					}
				}
				return failr(r,
					"$FileCreateMode not explicitly set in rsyslog config",
					"add '$FileCreateMode 0640' to /etc/rsyslog.conf to ensure log files are not world-readable")
			}},

		{ID: "4.2.6", Framework: cisBenchCIS, Level: 2, Section: "Audit",
			Description: "Ensure rsyslog is configured to send logs to a remote log host",
			Check: func(_ models.SecurityInfo, _ models.KernelSecurityInfo) models.CISResult {
				r := ruleByID("4.2.6")
				rsyslogPresent := false
				for _, p := range rsyslogBinPaths {
					if _, statErr := os.Stat(p); statErr == nil {
						rsyslogPresent = true
						break
					}
				}
				if !rsyslogPresent {
					return skipr(r, "rsyslog not installed")
				}
				hasRemote := func(data []byte) bool {
					for line := range strings.SplitSeq(string(data), "\n") {
						trimmed := strings.TrimSpace(line)
						if trimmed == "" || strings.HasPrefix(trimmed, "#") {
							continue
						}
						// Legacy format: *.* @@loghost:514 (TCP) / *.* @loghost:514 (UDP)
						if strings.Contains(trimmed, "@@") {
							return true
						}
						// RainerScript omfwd action
						if strings.Contains(trimmed, `type="omfwd"`) || strings.Contains(trimmed, "type='omfwd'") {
							return true
						}
					}
					return false
				}
				if data, err := os.ReadFile(rsyslogConfPath); err == nil { //nolint:gosec // package-level var
					if hasRemote(data) {
						return pass(r)
					}
				}
				if entries, err := os.ReadDir(rsyslogConfDPath); err == nil { //nolint:gosec // package-level var
					for _, e := range entries {
						if e.IsDir() || !strings.HasSuffix(e.Name(), ".conf") {
							continue
						}
						data, rdErr := os.ReadFile(filepath.Join(rsyslogConfDPath, e.Name())) //nolint:gosec
						if rdErr != nil {
							continue
						}
						if hasRemote(data) {
							return pass(r)
						}
					}
				}
				return failr(r, "no remote log forwarding found in rsyslog configuration",
					"add '*.* @@loghost.example.com:514' to /etc/rsyslog.d/99-remote.conf and restart rsyslog")
			}},

		{ID: "4.2.7", Framework: cisBenchCIS, Level: 1, Section: "Audit",
			Description: "Ensure permissions on all logfiles are configured (no world-read/write)",
			Check: func(_ models.SecurityInfo, _ models.KernelSecurityInfo) models.CISResult {
				r := ruleByID("4.2.7")
				if _, err := os.Stat(varLogPath); err != nil { //nolint:gosec // package-level var
					return skipr(r, "/var/log not readable")
				}
				var bad []string
				walkErr := filepath.WalkDir(varLogPath, func(path string, d fs.DirEntry, err error) error {
					if err != nil {
						return nil // skip unreadable dirs/files
					}
					if d.IsDir() {
						return nil
					}
					fi, siErr := d.Info()
					if siErr != nil {
						return nil
					}
					if fi.Mode().Perm()&0o006 != 0 {
						bad = append(bad, path)
					}
					return nil
				})
				_ = walkErr
				if len(bad) > 0 {
					shown := bad[:min(3, len(bad))]
					return failr(r,
						fmt.Sprintf("%d log file(s) have world-readable/writable permissions: %s",
							len(bad), strings.Join(shown, ", ")),
						"chmod go-rw /var/log/*.log")
				}
				return pass(r)
			}},

		// ── 4.3 Log rotation ──────────────────────────────────────────────────

		{ID: "4.3.1", Framework: cisBenchCIS, Level: 1, Section: "Audit",
			Description: "Ensure logrotate is configured",
			Check: func(_ models.SecurityInfo, _ models.KernelSecurityInfo) models.CISResult {
				r := ruleByID("4.3.1")
				hasConfig := func(data []byte) bool {
					for line := range strings.SplitSeq(string(data), "\n") {
						trimmed := strings.TrimSpace(line)
						if trimmed != "" && !strings.HasPrefix(trimmed, "#") {
							return true
						}
					}
					return false
				}
				if data, err := os.ReadFile(logrotateConfPath); err == nil { //nolint:gosec // package-level var
					if hasConfig(data) {
						return pass(r)
					}
				}
				if entries, err := os.ReadDir(logrotateConfDPath); err == nil { //nolint:gosec // package-level var
					for _, e := range entries {
						if e.IsDir() {
							continue
						}
						data, rdErr := os.ReadFile(filepath.Join(logrotateConfDPath, e.Name())) //nolint:gosec
						if rdErr != nil {
							continue
						}
						if hasConfig(data) {
							return pass(r)
						}
					}
				}
				return failr(r,
					"no logrotate configuration found",
					"install logrotate and ensure /etc/logrotate.conf or /etc/logrotate.d/ entries exist")
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
					return skipr(r, cisSkipSudoersUnreadable)
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
					return skipr(r, cisSkipSudoersUnreadable)
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
					return skipr(r, cisSkipSudoersUnreadable)
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
								cisFixInactiveUseradd)
						}
						if n > 30 {
							return failr(r, fmt.Sprintf("INACTIVE=%d days (must be ≤ 30)", n),
								cisFixInactiveUseradd)
						}
						return pass(r)
					}
				}
				return failr(r, "INACTIVE not set in /etc/default/useradd (no automatic lockout)",
					cisFixInactiveUseradd)
			}},

		{ID: "5.4.8", Framework: cisBenchCIS, Level: 1, Section: cisCatAuth,
			Description: "Ensure system accounts do not have interactive shells",
			Check: func(_ models.SecurityInfo, _ models.KernelSecurityInfo) models.CISResult {
				r := ruleByID("5.4.8")
				data, err := os.ReadFile(etcPasswdPath) //nolint:gosec // package-level var
				if err != nil {
					return skipr(r, cisSkipPasswdUnreadable)
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

		{ID: "5.4.9", Framework: cisBenchCIS, Level: 1, Section: cisCatAuth,
			Description: "Ensure password creation requirements are configured",
			Check: func(_ models.SecurityInfo, _ models.KernelSecurityInfo) models.CISResult {
				r := ruleByID("5.4.9")
				data, err := os.ReadFile(pwqualityConfPath) // #nosec G304 -- package-level var
				if err != nil {
					return skipr(r, "/etc/security/pwquality.conf not found (pam_pwquality not installed)")
				}
				minlen, found := -1, false
				for line := range strings.SplitSeq(string(data), "\n") {
					line = strings.TrimSpace(line)
					if line == "" || strings.HasPrefix(line, "#") {
						continue
					}
					parts := strings.SplitN(line, "=", 2)
					if len(parts) == 2 && strings.TrimSpace(parts[0]) == "minlen" {
						if n, parseErr := strconv.Atoi(strings.TrimSpace(parts[1])); parseErr == nil {
							minlen, found = n, true
						}
					}
				}
				if !found {
					return failr(r, "minlen not set in /etc/security/pwquality.conf",
						"add 'minlen = 14' to /etc/security/pwquality.conf")
				}
				if minlen < 14 {
					return failr(r, fmt.Sprintf("minlen = %d is below the CIS minimum of 14", minlen),
						"set 'minlen = 14' in /etc/security/pwquality.conf")
				}
				return pass(r)
			}},

		{ID: "5.4.10", Framework: cisBenchCIS, Level: 1, Section: cisCatAuth,
			Description: "Ensure lockout for failed password attempts is configured",
			Check: func(_ models.SecurityInfo, _ models.KernelSecurityInfo) models.CISResult {
				r := ruleByID("5.4.10")
				// Preferred: faillock.conf with deny ≤ 5
				if data, err := os.ReadFile(faillockConfPath); err == nil { // #nosec G304 -- package-level var
					for line := range strings.SplitSeq(string(data), "\n") {
						line = strings.TrimSpace(line)
						if line == "" || strings.HasPrefix(line, "#") {
							continue
						}
						parts := strings.SplitN(line, "=", 2)
						if len(parts) == 2 && strings.TrimSpace(parts[0]) == "deny" {
							denyStr := strings.TrimSpace(parts[1])
							n, parseErr := strconv.Atoi(denyStr)
							if parseErr != nil {
								// deny value is present but non-integer (e.g. "disabled") — misconfigured
								return failr(r, fmt.Sprintf("faillock deny value %q is not a valid integer", denyStr),
									"set 'deny = 5' in /etc/security/faillock.conf")
							}
							if n > 0 && n <= 5 {
								return pass(r)
							}
							return failr(r, fmt.Sprintf("faillock deny = %d exceeds CIS maximum of 5", n),
								"set 'deny = 5' in /etc/security/faillock.conf")
						}
					}
				}
				// Fallback: pam_faillock.so or pam_tally2.so in common-auth
				if data, err := os.ReadFile(pamCommonAuthPath); err == nil { // #nosec G304 -- package-level var
					for line := range strings.SplitSeq(string(data), "\n") {
						line = strings.TrimSpace(line)
						if strings.HasPrefix(line, "#") {
							continue
						}
						if strings.Contains(line, "pam_faillock.so") || strings.Contains(line, "pam_tally2.so") {
							return pass(r)
						}
					}
				}
				return failr(r, "account lockout (pam_faillock or pam_tally2) not configured",
					"add 'deny = 5' to /etc/security/faillock.conf or configure pam_faillock.so in /etc/pam.d/common-auth")
			}},

		{ID: "5.4.11", Framework: cisBenchCIS, Level: 1, Section: cisCatAuth,
			Description: "Ensure password hashing algorithm is up to date",
			Check: func(_ models.SecurityInfo, _ models.KernelSecurityInfo) models.CISResult {
				r := ruleByID("5.4.11")
				strong := map[string]bool{"sha512": true, "yescrypt": true}
				// Primary: ENCRYPT_METHOD in /etc/login.defs
				if data, err := os.ReadFile(loginDefsPath); err == nil { //nolint:gosec // package-level var
					for line := range strings.SplitSeq(string(data), "\n") {
						line = strings.TrimSpace(line)
						if line == "" || strings.HasPrefix(line, "#") {
							continue
						}
						fields := strings.Fields(line)
						if len(fields) == 2 && strings.EqualFold(fields[0], "ENCRYPT_METHOD") {
							method := strings.ToLower(fields[1])
							if strong[method] {
								return pass(r)
							}
							return failr(r, fmt.Sprintf("ENCRYPT_METHOD = %s is not SHA-512 or yescrypt", fields[1]),
								"set 'ENCRYPT_METHOD SHA512' in /etc/login.defs")
						}
					}
				}
				// Fallback: pam_unix.so sha512/yescrypt in common-password
				if data, err := os.ReadFile(pamCommonPasswordPath); err == nil { // #nosec G304 -- package-level var
					for line := range strings.SplitSeq(string(data), "\n") {
						line = strings.TrimSpace(line)
						if strings.HasPrefix(line, "#") || !strings.Contains(line, "pam_unix.so") {
							continue
						}
						lower := strings.ToLower(line)
						if strings.Contains(lower, "sha512") || strings.Contains(lower, "yescrypt") {
							return pass(r)
						}
					}
				}
				return failr(r, "password hashing algorithm not explicitly set to SHA-512 or yescrypt",
					"set 'ENCRYPT_METHOD SHA512' in /etc/login.defs")
			}},

		{ID: "5.4.12", Framework: cisBenchCIS, Level: 1, Section: cisCatAuth,
			Description: "Ensure password reuse is limited",
			Check: func(_ models.SecurityInfo, _ models.KernelSecurityInfo) models.CISResult {
				r := ruleByID("5.4.12")
				data, err := os.ReadFile(pamCommonPasswordPath) // #nosec G304 -- package-level var
				if err != nil {
					return skipr(r, "/etc/pam.d/common-password not readable")
				}
				for line := range strings.SplitSeq(string(data), "\n") {
					line = strings.TrimSpace(line)
					if strings.HasPrefix(line, "#") {
						continue
					}
					if !strings.Contains(line, "pam_unix.so") && !strings.Contains(line, "pam_pwhistory.so") {
						continue
					}
					for field := range strings.FieldsSeq(line) {
						rest, ok := strings.CutPrefix(field, "remember=")
						if !ok {
							continue
						}
						n, parseErr := strconv.Atoi(rest)
						if parseErr != nil {
							continue
						}
						if n < 5 {
							return failr(r, fmt.Sprintf("password remember = %d is below CIS minimum of 5", n),
								"add 'remember=5' to pam_unix.so in /etc/pam.d/common-password")
						}
						return pass(r)
					}
				}
				return failr(r, "password reuse limit (remember=) not configured in /etc/pam.d/common-password",
					"add 'remember=5' to pam_unix.so or pam_pwhistory.so in /etc/pam.d/common-password")
			}},

		// ── 5.4.13-5.4.15 additional PAM faillock + pwquality settings ───────

		{ID: "5.4.13", Framework: cisBenchCIS, Level: 1, Section: cisCatAuth,
			Description: "Ensure PAM lockout unlock time is 15 minutes or more (unlock_time >= 900)",
			Check: func(_ models.SecurityInfo, _ models.KernelSecurityInfo) models.CISResult {
				r := ruleByID("5.4.13")
				data, err := os.ReadFile(faillockConfPath) // #nosec G304 -- package-level var
				if err != nil {
					return skipr(r, "/etc/security/faillock.conf not found (pam_faillock not installed)")
				}
				for line := range strings.SplitSeq(string(data), "\n") {
					line = strings.TrimSpace(line)
					if line == "" || strings.HasPrefix(line, "#") {
						continue
					}
					parts := strings.SplitN(line, "=", 2)
					if len(parts) == 2 && strings.TrimSpace(parts[0]) == "unlock_time" {
						n, parseErr := strconv.Atoi(strings.TrimSpace(parts[1]))
						if parseErr != nil {
							return failr(r, fmt.Sprintf("unlock_time=%q is not a valid integer", strings.TrimSpace(parts[1])),
								"set 'unlock_time = 900' in /etc/security/faillock.conf")
						}
						if n < 900 {
							return failr(r, fmt.Sprintf("unlock_time = %d is below CIS minimum of 900 seconds", n),
								"set 'unlock_time = 900' in /etc/security/faillock.conf")
						}
						return pass(r)
					}
				}
				return failr(r, "unlock_time not configured in /etc/security/faillock.conf",
					"add 'unlock_time = 900' to /etc/security/faillock.conf")
			}},

		{ID: "5.4.14", Framework: cisBenchCIS, Level: 1, Section: cisCatAuth,
			Description: "Ensure PAM lockout failure window is configured (fail_interval >= 900)",
			Check: func(_ models.SecurityInfo, _ models.KernelSecurityInfo) models.CISResult {
				r := ruleByID("5.4.14")
				data, err := os.ReadFile(faillockConfPath) // #nosec G304 -- package-level var
				if err != nil {
					return skipr(r, "/etc/security/faillock.conf not found (pam_faillock not installed)")
				}
				for line := range strings.SplitSeq(string(data), "\n") {
					line = strings.TrimSpace(line)
					if line == "" || strings.HasPrefix(line, "#") {
						continue
					}
					parts := strings.SplitN(line, "=", 2)
					if len(parts) == 2 && strings.TrimSpace(parts[0]) == "fail_interval" {
						n, parseErr := strconv.Atoi(strings.TrimSpace(parts[1]))
						if parseErr != nil {
							return failr(r, fmt.Sprintf("fail_interval=%q is not a valid integer", strings.TrimSpace(parts[1])),
								"set 'fail_interval = 900' in /etc/security/faillock.conf")
						}
						if n < 900 {
							return failr(r, fmt.Sprintf("fail_interval = %d is below CIS minimum of 900 seconds", n),
								"set 'fail_interval = 900' in /etc/security/faillock.conf")
						}
						return pass(r)
					}
				}
				return failr(r, "fail_interval not configured in /etc/security/faillock.conf",
					"add 'fail_interval = 900' to /etc/security/faillock.conf")
			}},

		{ID: "5.4.15", Framework: cisBenchCIS, Level: 1, Section: cisCatAuth,
			Description: "Ensure password complexity class requirement is configured (minclass >= 3 or credit settings)",
			Check: func(_ models.SecurityInfo, _ models.KernelSecurityInfo) models.CISResult {
				r := ruleByID("5.4.15")
				data, err := os.ReadFile(pwqualityConfPath) // #nosec G304 -- package-level var
				if err != nil {
					return skipr(r, "/etc/security/pwquality.conf not found (pam_pwquality not installed)")
				}
				settings := map[string]int{}
				for line := range strings.SplitSeq(string(data), "\n") {
					line = strings.TrimSpace(line)
					if line == "" || strings.HasPrefix(line, "#") {
						continue
					}
					parts := strings.SplitN(line, "=", 2)
					if len(parts) != 2 {
						continue
					}
					key := strings.TrimSpace(parts[0])
					val := strings.TrimSpace(parts[1])
					if n, parseErr := strconv.Atoi(val); parseErr == nil {
						settings[key] = n
					}
				}
				if v, ok := settings["minclass"]; ok && v >= 3 {
					return pass(r)
				}
				negCredit := 0
				for _, k := range []string{"dcredit", "ucredit", "ocredit", "lcredit"} {
					if v, ok := settings[k]; ok && v < 0 {
						negCredit++
					}
				}
				if negCredit >= 3 {
					return pass(r)
				}
				return failr(r,
					"password complexity not configured (minclass < 3 and fewer than 3 credit settings are negative)",
					"add 'minclass = 4' to /etc/security/pwquality.conf")
			}},

		// ── 5.4.16-5.4.17 pam_pwquality retry + PAM nullok ───────────────────

		{ID: "5.4.16", Framework: cisBenchCIS, Level: 1, Section: cisCatAuth,
			Description: "Ensure pam_pwquality is configured with retry ≤ 3",
			Check: func(_ models.SecurityInfo, _ models.KernelSecurityInfo) models.CISResult {
				r := ruleByID("5.4.16")
				data, err := os.ReadFile(pamCommonPasswordPath) // #nosec G304 -- package-level var
				if err != nil {
					return skipr(r, "/etc/pam.d/common-password not readable")
				}
				for line := range strings.SplitSeq(string(data), "\n") {
					line = strings.TrimSpace(line)
					if strings.HasPrefix(line, "#") || !strings.Contains(line, "pam_pwquality.so") {
						continue
					}
					for field := range strings.FieldsSeq(line) {
						rest, ok := strings.CutPrefix(field, "retry=")
						if !ok {
							continue
						}
						n, parseErr := strconv.Atoi(rest)
						if parseErr != nil {
							continue
						}
						if n > 3 {
							return failr(r, fmt.Sprintf("pam_pwquality retry=%d exceeds CIS maximum of 3", n),
								"set 'retry=3' on the pam_pwquality.so line in /etc/pam.d/common-password")
						}
						return pass(r)
					}
				}
				return failr(r, "pam_pwquality.so with retry= not found in /etc/pam.d/common-password",
					"add 'retry=3' to the pam_pwquality.so line in /etc/pam.d/common-password")
			}},

		{ID: "5.4.17", Framework: cisBenchCIS, Level: 1, Section: cisCatAuth,
			Description: "Ensure PAM does not permit login with null passwords (nullok absent)",
			Check: func(_ models.SecurityInfo, _ models.KernelSecurityInfo) models.CISResult {
				r := ruleByID("5.4.17")
				entries, err := os.ReadDir(pamDPath) //nolint:gosec // package-level var
				if err != nil {
					return skipr(r, "/etc/pam.d not readable")
				}
				for _, entry := range entries {
					if entry.IsDir() {
						continue
					}
					path := filepath.Join(pamDPath, entry.Name()) //nolint:gosec
					data, rdErr := os.ReadFile(path)              //nolint:gosec
					if rdErr != nil {
						continue
					}
					for line := range strings.SplitSeq(string(data), "\n") {
						line = strings.TrimSpace(line)
						if strings.HasPrefix(line, "#") {
							continue
						}
						for field := range strings.FieldsSeq(line) {
							if field == "nullok" {
								return failr(r,
									fmt.Sprintf("'nullok' found in %s — empty passwords permitted via PAM", path),
									"remove 'nullok' from all PAM configuration files in /etc/pam.d/")
							}
						}
					}
				}
				return pass(r)
			}},

		{ID: "5.3.5", Framework: cisBenchCIS, Level: 1, Section: cisCatAuth,
			Description: "Ensure sudo authentication timeout is 15 minutes or less",
			Check: func(sec models.SecurityInfo, _ models.KernelSecurityInfo) models.CISResult {
				r := ruleByID("5.3.5")
				if sec.SudoersUnreadable {
					return skipr(r, cisSkipSudoersUnreadable)
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

		// ── 5.5 User Accounts and Environment ───────────────────────────────

		{ID: "5.5.1", Framework: cisBenchCIS, Level: 1, Section: cisCatAuth,
			Description: "Ensure root login is restricted to system console",
			Check: func(_ models.SecurityInfo, _ models.KernelSecurityInfo) models.CISResult {
				r := ruleByID("5.5.1")
				data, err := os.ReadFile(securettyPath) // #nosec G304 -- package-level var
				if err != nil {
					return failr(r, "/etc/securetty missing — root can login from any terminal",
						"create /etc/securetty listing only required console devices (e.g. tty1)")
				}
				for line := range strings.SplitSeq(string(data), "\n") {
					line = strings.TrimSpace(line)
					if line != "" && !strings.HasPrefix(line, "#") {
						return pass(r)
					}
				}
				return failr(r, "/etc/securetty is empty — no terminals restricted",
					"add allowed console ttys to /etc/securetty (e.g. tty1)")
			}},

		{ID: "5.5.2", Framework: cisBenchCIS, Level: 1, Section: cisCatAuth,
			Description: "Ensure access to the su command is restricted",
			Check: func(_ models.SecurityInfo, _ models.KernelSecurityInfo) models.CISResult {
				r := ruleByID("5.5.2")
				data, err := os.ReadFile(pamSuPath) // #nosec G304 -- package-level var
				if err != nil {
					return skipr(r, "/etc/pam.d/su not readable")
				}
				for line := range strings.SplitSeq(string(data), "\n") {
					line = strings.TrimSpace(line)
					if strings.HasPrefix(line, "#") || line == "" {
						continue
					}
					// PAM line format: type control module [options]
					// Control must be "required" or "requisite" — "optional" does not restrict.
					fields := strings.Fields(line)
					if len(fields) >= 3 &&
						(fields[1] == "required" || fields[1] == "requisite") &&
						strings.Contains(fields[2], "pam_wheel.so") {
						for _, f := range fields[3:] {
							if f == "use_uid" {
								return pass(r)
							}
						}
					}
				}
				return failr(r, "pam_wheel.so use_uid not found in /etc/pam.d/su with required/requisite control",
					"add 'auth required pam_wheel.so use_uid' to /etc/pam.d/su to restrict su to wheel group")
			}},

		{ID: "5.5.3", Framework: cisBenchCIS, Level: 1, Section: cisCatAuth,
			Description: "Ensure default user umask is 027 or more restrictive",
			Check: func(_ models.SecurityInfo, _ models.KernelSecurityInfo) models.CISResult {
				r := ruleByID("5.5.3")
				// isRestrictive returns true if octal umask string is 027 or more restrictive
				// (all bits of 027 must be set: group-write + all-other).
				isRestrictive := func(s string) (bool, bool) { // (valid, ok)
					s = strings.TrimSpace(s)
					v, err := strconv.ParseInt(s, 8, 32)
					if err != nil {
						return false, false
					}
					return (v & 0o027) == 0o027, true
				}
				// scanFile collects umask values from a file's lines.
				// login.defs uses "UMASK <value>"; shell files use "umask <value>".
				scanFile := func(data []byte) []string {
					var vals []string
					for line := range strings.SplitSeq(string(data), "\n") {
						line = strings.TrimSpace(line)
						if line == "" || strings.HasPrefix(line, "#") {
							continue
						}
						fields := strings.Fields(line)
						if len(fields) == 2 && strings.EqualFold(fields[0], "umask") {
							vals = append(vals, fields[1])
						}
					}
					return vals
				}
				var allVals []string
				if data, err := os.ReadFile(loginDefsPath); err == nil { //nolint:gosec // package-level var
					for line := range strings.SplitSeq(string(data), "\n") {
						line = strings.TrimSpace(line)
						if line == "" || strings.HasPrefix(line, "#") {
							continue
						}
						fields := strings.Fields(line)
						if len(fields) == 2 && strings.EqualFold(fields[0], "UMASK") {
							allVals = append(allVals, fields[1])
						}
					}
				}
				if data, err := os.ReadFile(etcProfilePath); err == nil { //nolint:gosec // package-level var
					allVals = append(allVals, scanFile(data)...)
				}
				if entries, err := os.ReadDir(etcProfileDPath); err == nil { //nolint:gosec // package-level var
					for _, e := range entries {
						if e.IsDir() || !strings.HasSuffix(e.Name(), ".sh") {
							continue
						}
						if data, err := os.ReadFile(filepath.Join(etcProfileDPath, e.Name())); err == nil { //nolint:gosec
							allVals = append(allVals, scanFile(data)...)
						}
					}
				}
				if data, err := os.ReadFile(etcBashrcPath); err == nil { //nolint:gosec // package-level var
					allVals = append(allVals, scanFile(data)...)
				}
				if len(allVals) == 0 {
					return failr(r, "umask not configured in /etc/login.defs, /etc/profile, /etc/profile.d/*.sh, or /etc/bash.bashrc",
						"add 'umask 027' to /etc/profile or a /etc/profile.d/*.sh drop-in")
				}
				anyValid := false
				for _, val := range allVals {
					ok, valid := isRestrictive(val)
					if !valid {
						continue
					}
					anyValid = true
					if !ok {
						return failr(r, fmt.Sprintf("umask %s is less restrictive than 027", val),
							"set 'umask 027' in /etc/profile or /etc/login.defs (UMASK 027)")
					}
				}
				if len(allVals) > 0 && !anyValid {
					return skipr(r, "umask values found but none were parseable as octal (variable references?)")
				}
				return pass(r)
			}},

		{ID: "5.5.4", Framework: cisBenchCIS, Level: 1, Section: cisCatAuth,
			Description: "Ensure default user shell timeout is 900 seconds or less",
			Check: func(_ models.SecurityInfo, _ models.KernelSecurityInfo) models.CISResult {
				r := ruleByID("5.5.4")
				// parseTMOUT extracts TMOUT value from a line (returns -1 if not found).
				// Handles: TMOUT=900, readonly TMOUT=900, export TMOUT=900.
				parseTMOUT := func(line string) int {
					line = strings.TrimSpace(line)
					for _, prefix := range []string{"readonly ", "export ", ""} {
						rest, ok := strings.CutPrefix(line, prefix)
						if !ok {
							continue
						}
						rest2, ok2 := strings.CutPrefix(rest, "TMOUT=")
						if !ok2 {
							continue
						}
						n, err := strconv.Atoi(strings.TrimSpace(rest2))
						if err == nil {
							return n
						}
					}
					return -1
				}
				scanTMOUT := func(data []byte) int {
					for line := range strings.SplitSeq(string(data), "\n") {
						if strings.HasPrefix(strings.TrimSpace(line), "#") {
							continue
						}
						if n := parseTMOUT(line); n >= 0 {
							return n
						}
					}
					return -1
				}
				found := -1
				if data, err := os.ReadFile(etcProfilePath); err == nil { //nolint:gosec // package-level var
					if n := scanTMOUT(data); n >= 0 {
						found = n
					}
				}
				if entries, err := os.ReadDir(etcProfileDPath); err == nil && found < 0 { //nolint:gosec // package-level var
					for _, e := range entries {
						if e.IsDir() || !strings.HasSuffix(e.Name(), ".sh") {
							continue
						}
						if data, err := os.ReadFile(filepath.Join(etcProfileDPath, e.Name())); err == nil { //nolint:gosec
							if n := scanTMOUT(data); n >= 0 {
								found = n
								break
							}
						}
					}
				}
				if found < 0 {
					if data, err := os.ReadFile(etcBashrcPath); err == nil { //nolint:gosec // package-level var
						found = scanTMOUT(data)
					}
				}
				if found < 0 {
					return failr(r, "TMOUT not set in /etc/profile, /etc/profile.d/*.sh, or /etc/bash.bashrc",
						"add 'readonly TMOUT=900' to /etc/profile.d/timeout.sh")
				}
				if found > 900 {
					return failr(r, fmt.Sprintf("TMOUT=%d exceeds CIS maximum of 900 seconds", found),
						"set 'readonly TMOUT=900' in /etc/profile.d/timeout.sh")
				}
				return pass(r)
			}},

		// ── 5.1 Cron Daemon Configuration ────────────────────────────────────

		{ID: "5.1.1", Framework: cisBenchCIS, Level: 1, Section: "Cron",
			Description: "Ensure cron daemon is enabled and running",
			Check: func(_ models.SecurityInfo, _ models.KernelSecurityInfo) models.CISResult {
				r := ruleByID("5.1.1")
				for _, p := range cronWantsPaths {
					if _, err := os.Stat(p); err == nil { // #nosec G304 -- hardcoded systemd paths
						return pass(r)
					}
				}
				return failr(r, "cron daemon not found in systemd wants directory — may not be enabled",
					"systemctl enable --now cron || systemctl enable --now crond")
			}},

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
			Description: "Ensure cron is restricted to authorized users (/etc/cron.allow, not /etc/cron.deny)",
			Check: func(_ models.SecurityInfo, _ models.KernelSecurityInfo) models.CISResult {
				r := ruleByID("5.1.8")
				_, errAllow := os.Stat(cronAllowPath)
				_, errDeny := os.Stat(cronDenyPath)
				switch {
				case errAllow == nil && errDeny != nil:
					return pass(r) // allow exists, no deny — correct allowlist model
				case errAllow == nil && errDeny == nil:
					return failr(r, "both /etc/cron.allow and /etc/cron.deny exist; only cron.allow should be present",
						"remove /etc/cron.deny — the allowlist model requires only /etc/cron.allow")
				case errAllow != nil && errDeny == nil:
					return failr(r, "/etc/cron.deny exists without /etc/cron.allow — use allowlist model",
						"create /etc/cron.allow with authorized users and remove /etc/cron.deny")
				default:
					return failr(r, "neither /etc/cron.allow nor /etc/cron.deny exists",
						"create /etc/cron.allow with authorized users (one per line)")
				}
			}},

		{ID: "5.1.9", Framework: cisBenchCIS, Level: 1, Section: "Cron",
			Description: "Ensure at is restricted to authorized users (/etc/at.allow, not /etc/at.deny)",
			Check: func(_ models.SecurityInfo, _ models.KernelSecurityInfo) models.CISResult {
				r := ruleByID("5.1.9")
				_, errAllow := os.Stat(atAllowPath)
				_, errDeny := os.Stat(atDenyPath)
				switch {
				case errAllow == nil && errDeny != nil:
					return pass(r) // allow exists, no deny — correct allowlist model
				case errAllow == nil && errDeny == nil:
					return failr(r, "both /etc/at.allow and /etc/at.deny exist; only at.allow should be present",
						"remove /etc/at.deny — the allowlist model requires only /etc/at.allow")
				case errAllow != nil && errDeny == nil:
					return failr(r, "/etc/at.deny exists without /etc/at.allow — use allowlist model",
						"create /etc/at.allow with authorized users and remove /etc/at.deny")
				default:
					return failr(r, "neither /etc/at.allow nor /etc/at.deny exists",
						"create /etc/at.allow with authorized users (one per line)")
				}
			}},
		{ID: "5.1.10", Framework: cisBenchCIS, Level: 1, Section: "Cron",
			Description: "Ensure /etc/crontab is owned by root:root",
			Check: func(_ models.SecurityInfo, _ models.KernelSecurityInfo) models.CISResult {
				return checkFileOwnerRootRoot(ruleByID("5.1.10"), "/etc/crontab", "chown root:root /etc/crontab")
			}},
		{ID: "5.1.11", Framework: cisBenchCIS, Level: 1, Section: "Cron",
			Description: "Ensure /etc/cron.hourly is owned by root:root",
			Check: func(_ models.SecurityInfo, _ models.KernelSecurityInfo) models.CISResult {
				return checkFileOwnerRootRoot(ruleByID("5.1.11"), "/etc/cron.hourly", "chown root:root /etc/cron.hourly")
			}},
		{ID: "5.1.12", Framework: cisBenchCIS, Level: 1, Section: "Cron",
			Description: "Ensure /etc/cron.daily is owned by root:root",
			Check: func(_ models.SecurityInfo, _ models.KernelSecurityInfo) models.CISResult {
				return checkFileOwnerRootRoot(ruleByID("5.1.12"), "/etc/cron.daily", "chown root:root /etc/cron.daily")
			}},
		{ID: "5.1.13", Framework: cisBenchCIS, Level: 1, Section: "Cron",
			Description: "Ensure /etc/cron.weekly is owned by root:root",
			Check: func(_ models.SecurityInfo, _ models.KernelSecurityInfo) models.CISResult {
				return checkFileOwnerRootRoot(ruleByID("5.1.13"), "/etc/cron.weekly", "chown root:root /etc/cron.weekly")
			}},
		{ID: "5.1.14", Framework: cisBenchCIS, Level: 1, Section: "Cron",
			Description: "Ensure /etc/cron.monthly is owned by root:root",
			Check: func(_ models.SecurityInfo, _ models.KernelSecurityInfo) models.CISResult {
				return checkFileOwnerRootRoot(ruleByID("5.1.14"), "/etc/cron.monthly", "chown root:root /etc/cron.monthly")
			}},
		{ID: "5.1.15", Framework: cisBenchCIS, Level: 1, Section: "Cron",
			Description: "Ensure /etc/cron.d is owned by root:root",
			Check: func(_ models.SecurityInfo, _ models.KernelSecurityInfo) models.CISResult {
				return checkFileOwnerRootRoot(ruleByID("5.1.15"), "/etc/cron.d", "chown root:root /etc/cron.d")
			}},

		// ── 5.1.16-5.1.23 cron/at allow-deny file permissions + ownership ──────
		// These files are optional: if absent the rule SKIPs (checkFilePerm and
		// checkFileOwnerRootRoot both return SKIP when os.Stat fails).

		{ID: "5.1.16", Framework: cisBenchCIS, Level: 1, Section: "Cron",
			Description: "Ensure /etc/cron.allow permissions are configured (0600)",
			Check: func(_ models.SecurityInfo, _ models.KernelSecurityInfo) models.CISResult {
				return checkFilePerm(ruleByID("5.1.16"), cronAllowPath, 0o600, "chmod 600 /etc/cron.allow")
			}},
		{ID: "5.1.17", Framework: cisBenchCIS, Level: 1, Section: "Cron",
			Description: "Ensure /etc/cron.allow is owned by root:root",
			Check: func(_ models.SecurityInfo, _ models.KernelSecurityInfo) models.CISResult {
				return checkFileOwnerRootRoot(ruleByID("5.1.17"), cronAllowPath, "chown root:root /etc/cron.allow")
			}},
		{ID: "5.1.18", Framework: cisBenchCIS, Level: 1, Section: "Cron",
			Description: "Ensure /etc/cron.deny permissions are configured (0600)",
			Check: func(_ models.SecurityInfo, _ models.KernelSecurityInfo) models.CISResult {
				return checkFilePerm(ruleByID("5.1.18"), cronDenyPath, 0o600, "chmod 600 /etc/cron.deny")
			}},
		{ID: "5.1.19", Framework: cisBenchCIS, Level: 1, Section: "Cron",
			Description: "Ensure /etc/cron.deny is owned by root:root",
			Check: func(_ models.SecurityInfo, _ models.KernelSecurityInfo) models.CISResult {
				return checkFileOwnerRootRoot(ruleByID("5.1.19"), cronDenyPath, "chown root:root /etc/cron.deny")
			}},
		{ID: "5.1.20", Framework: cisBenchCIS, Level: 1, Section: "Cron",
			Description: "Ensure /etc/at.allow permissions are configured (0600)",
			Check: func(_ models.SecurityInfo, _ models.KernelSecurityInfo) models.CISResult {
				return checkFilePerm(ruleByID("5.1.20"), atAllowPath, 0o600, "chmod 600 /etc/at.allow")
			}},
		{ID: "5.1.21", Framework: cisBenchCIS, Level: 1, Section: "Cron",
			Description: "Ensure /etc/at.allow is owned by root:root",
			Check: func(_ models.SecurityInfo, _ models.KernelSecurityInfo) models.CISResult {
				return checkFileOwnerRootRoot(ruleByID("5.1.21"), atAllowPath, "chown root:root /etc/at.allow")
			}},
		{ID: "5.1.22", Framework: cisBenchCIS, Level: 1, Section: "Cron",
			Description: "Ensure /etc/at.deny permissions are configured (0600)",
			Check: func(_ models.SecurityInfo, _ models.KernelSecurityInfo) models.CISResult {
				return checkFilePerm(ruleByID("5.1.22"), atDenyPath, 0o600, "chmod 600 /etc/at.deny")
			}},
		{ID: "5.1.23", Framework: cisBenchCIS, Level: 1, Section: "Cron",
			Description: "Ensure /etc/at.deny is owned by root:root",
			Check: func(_ models.SecurityInfo, _ models.KernelSecurityInfo) models.CISResult {
				return checkFileOwnerRootRoot(ruleByID("5.1.23"), atDenyPath, "chown root:root /etc/at.deny")
			}},

		{ID: "1.1.19", Framework: cisBenchCIS, Level: 1, Section: "Filesystem",
			Description: "Ensure nosuid option is set on removable media partitions",
			Check: func(_ models.SecurityInfo, _ models.KernelSecurityInfo) models.CISResult {
				return checkRemovableMediaOption(ruleByID("1.1.19"), "nosuid")
			}},

		{ID: "1.1.20", Framework: cisBenchCIS, Level: 1, Section: "Filesystem",
			Description: "Ensure noexec option is set on removable media partitions",
			Check: func(_ models.SecurityInfo, _ models.KernelSecurityInfo) models.CISResult {
				return checkRemovableMediaOption(ruleByID("1.1.20"), "noexec")
			}},

		{ID: "1.1.21", Framework: cisBenchCIS, Level: 1, Section: "Filesystem",
			Description: "Ensure nodev option is set on removable media partitions",
			Check: func(_ models.SecurityInfo, _ models.KernelSecurityInfo) models.CISResult {
				return checkRemovableMediaOption(ruleByID("1.1.21"), "nodev")
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

		{ID: "1.1.23", Framework: cisBenchCIS, Level: 2, Section: "Filesystem",
			Description: "Ensure /var is on a separate partition",
			Check: func(_ models.SecurityInfo, _ models.KernelSecurityInfo) models.CISResult {
				return checkSeparateMountPoint(ruleByID("1.1.23"), "/var",
					"create a separate /var partition and add to /etc/fstab")
			}},

		{ID: "1.1.24", Framework: cisBenchCIS, Level: 1, Section: "Filesystem",
			Description: "Ensure /var/tmp is on a separate partition",
			Check: func(_ models.SecurityInfo, _ models.KernelSecurityInfo) models.CISResult {
				return checkSeparateMountPoint(ruleByID("1.1.24"), cisPathVarTmp,
					"create a separate /var/tmp partition and add to /etc/fstab")
			}},

		{ID: "1.1.25", Framework: cisBenchCIS, Level: 2, Section: "Filesystem",
			Description: "Ensure /home is on a separate partition",
			Check: func(_ models.SecurityInfo, _ models.KernelSecurityInfo) models.CISResult {
				return checkSeparateMountPoint(ruleByID("1.1.25"), "/home",
					"create a separate /home partition and add to /etc/fstab")
			}},

		{ID: "1.1.26", Framework: cisBenchCIS, Level: 2, Section: "Filesystem",
			Description: "Ensure nodev option set on /var/log partition",
			Check: func(_ models.SecurityInfo, _ models.KernelSecurityInfo) models.CISResult {
				return checkMountOption(ruleByID("1.1.26"), varLogPath, "nodev",
					"add 'nodev' to /var/log mount options in /etc/fstab")
			}},

		{ID: "1.1.27", Framework: cisBenchCIS, Level: 2, Section: "Filesystem",
			Description: "Ensure nosuid option set on /var/log partition",
			Check: func(_ models.SecurityInfo, _ models.KernelSecurityInfo) models.CISResult {
				return checkMountOption(ruleByID("1.1.27"), varLogPath, "nosuid",
					"add 'nosuid' to /var/log mount options in /etc/fstab")
			}},

		{ID: "1.1.28", Framework: cisBenchCIS, Level: 2, Section: "Filesystem",
			Description: "Ensure noexec option set on /var/log partition",
			Check: func(_ models.SecurityInfo, _ models.KernelSecurityInfo) models.CISResult {
				return checkMountOption(ruleByID("1.1.28"), varLogPath, "noexec",
					"add 'noexec' to /var/log mount options in /etc/fstab")
			}},
		{ID: "1.1.29", Framework: cisBenchCIS, Level: 2, Section: "Filesystem",
			Description: "Ensure nodev option set on /var partition",
			Check: func(_ models.SecurityInfo, _ models.KernelSecurityInfo) models.CISResult {
				return checkMountOption(ruleByID("1.1.29"), "/var", "nodev",
					"add 'nodev' to /var mount options in /etc/fstab")
			}},
		{ID: "1.1.30", Framework: cisBenchCIS, Level: 2, Section: "Filesystem",
			Description: "Ensure nosuid option set on /var partition",
			Check: func(_ models.SecurityInfo, _ models.KernelSecurityInfo) models.CISResult {
				return checkMountOption(ruleByID("1.1.30"), "/var", "nosuid",
					"add 'nosuid' to /var mount options in /etc/fstab")
			}},
		{ID: "1.1.31", Framework: cisBenchCIS, Level: 2, Section: "Filesystem",
			Description: "Ensure nosuid option set on /home partition",
			Check: func(_ models.SecurityInfo, _ models.KernelSecurityInfo) models.CISResult {
				return checkMountOption(ruleByID("1.1.31"), "/home", "nosuid",
					"add 'nosuid' to /home mount options in /etc/fstab")
			}},
		{ID: "1.1.32", Framework: cisBenchCIS, Level: 2, Section: "Filesystem",
			Description: "Ensure noexec option set on /home partition",
			Check: func(_ models.SecurityInfo, _ models.KernelSecurityInfo) models.CISResult {
				return checkMountOption(ruleByID("1.1.32"), "/home", "noexec",
					"add 'noexec' to /home mount options in /etc/fstab")
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

		{ID: "6.1.15", Framework: cisBenchCIS, Level: 1, Section: cisCatFiles,
			Description: "Ensure /etc/group- is owned by root:root",
			Check: func(_ models.SecurityInfo, _ models.KernelSecurityInfo) models.CISResult {
				return checkFileOwnerRootRoot(ruleByID("6.1.15"), "/etc/group-", "chown root:root /etc/group-")
			}},

		{ID: "6.1.16", Framework: cisBenchCIS, Level: 1, Section: cisCatFiles,
			Description: "Ensure /etc/gshadow is owned by root:root or root:shadow",
			Check: func(_ models.SecurityInfo, _ models.KernelSecurityInfo) models.CISResult {
				return checkFileOwnerRootRootOrShadow(ruleByID("6.1.16"), "/etc/gshadow", "chown root:shadow /etc/gshadow")
			}},

		{ID: "6.1.17", Framework: cisBenchCIS, Level: 1, Section: cisCatFiles,
			Description: "Ensure /etc/gshadow- is owned by root:root or root:shadow",
			Check: func(_ models.SecurityInfo, _ models.KernelSecurityInfo) models.CISResult {
				return checkFileOwnerRootRootOrShadow(ruleByID("6.1.17"), "/etc/gshadow-", "chown root:shadow /etc/gshadow-")
			}},
		{ID: "6.1.18", Framework: cisBenchCIS, Level: 1, Section: cisCatFiles,
			Description: "Ensure /etc/sudoers permissions are 440 or stricter",
			Check: func(_ models.SecurityInfo, _ models.KernelSecurityInfo) models.CISResult {
				r := ruleByID("6.1.18")
				return checkFilePerm(r, "/etc/sudoers", 0o440, "chmod 440 /etc/sudoers")
			}},
		{ID: "6.1.19", Framework: cisBenchCIS, Level: 1, Section: cisCatFiles,
			Description: "Ensure /etc/sudoers is owned by root:root",
			Check: func(_ models.SecurityInfo, _ models.KernelSecurityInfo) models.CISResult {
				return checkFileOwnerRootRoot(ruleByID("6.1.19"), "/etc/sudoers", "chown root:root /etc/sudoers")
			}},
		{ID: "6.1.20", Framework: cisBenchCIS, Level: 1, Section: cisCatFiles,
			Description: "Ensure /etc/sudoers.d permissions are 750 or stricter",
			Check: func(_ models.SecurityInfo, _ models.KernelSecurityInfo) models.CISResult {
				r := ruleByID("6.1.20")
				return checkFilePerm(r, "/etc/sudoers.d", 0o750, "chmod 750 /etc/sudoers.d")
			}},
		{ID: "6.1.21", Framework: cisBenchCIS, Level: 1, Section: cisCatFiles,
			Description: "Ensure /etc/audit/auditd.conf permissions are 640 or stricter",
			Check: func(_ models.SecurityInfo, _ models.KernelSecurityInfo) models.CISResult {
				r := ruleByID("6.1.21")
				return checkFilePerm(r, auditdConfPath, 0o640, "chmod 640 /etc/audit/auditd.conf")
			}},
		{ID: "6.1.22", Framework: cisBenchCIS, Level: 1, Section: cisCatFiles,
			Description: "Ensure /etc/audit/auditd.conf is owned by root:root",
			Check: func(_ models.SecurityInfo, _ models.KernelSecurityInfo) models.CISResult {
				return checkFileOwnerRootRoot(ruleByID("6.1.22"), auditdConfPath, "chown root:root /etc/audit/auditd.conf")
			}},
		{ID: "6.1.23", Framework: cisBenchCIS, Level: 1, Section: cisCatFiles,
			Description: "Ensure /etc/hosts permissions are configured (644 or more restrictive)",
			Check: func(_ models.SecurityInfo, _ models.KernelSecurityInfo) models.CISResult {
				r := ruleByID("6.1.23")
				return checkFilePerm(r, "/etc/hosts", 0o644, "chmod 644 /etc/hosts")
			}},
		{ID: "6.1.24", Framework: cisBenchCIS, Level: 1, Section: cisCatFiles,
			Description: "Ensure /etc/hosts.allow permissions are configured (644 or more restrictive)",
			Check: func(_ models.SecurityInfo, _ models.KernelSecurityInfo) models.CISResult {
				r := ruleByID("6.1.24")
				return checkFilePerm(r, "/etc/hosts.allow", 0o644, "chmod 644 /etc/hosts.allow")
			}},
		{ID: "6.1.25", Framework: cisBenchCIS, Level: 1, Section: cisCatFiles,
			Description: "Ensure /etc/hosts.deny permissions are configured (644 or more restrictive)",
			Check: func(_ models.SecurityInfo, _ models.KernelSecurityInfo) models.CISResult {
				r := ruleByID("6.1.25")
				return checkFilePerm(r, "/etc/hosts.deny", 0o644, "chmod 644 /etc/hosts.deny")
			}},
		{ID: "6.1.26", Framework: cisBenchCIS, Level: 1, Section: cisCatFiles,
			Description: "Ensure /etc/hosts is owned by root:root",
			Check: func(_ models.SecurityInfo, _ models.KernelSecurityInfo) models.CISResult {
				return checkFileOwnerRootRoot(ruleByID("6.1.26"), "/etc/hosts", "chown root:root /etc/hosts")
			}},
		{ID: "6.1.27", Framework: cisBenchCIS, Level: 1, Section: cisCatFiles,
			Description: "Ensure /etc/hosts.allow is owned by root:root",
			Check: func(_ models.SecurityInfo, _ models.KernelSecurityInfo) models.CISResult {
				return checkFileOwnerRootRoot(ruleByID("6.1.27"), "/etc/hosts.allow", "chown root:root /etc/hosts.allow")
			}},
		{ID: "6.1.28", Framework: cisBenchCIS, Level: 1, Section: cisCatFiles,
			Description: "Ensure /etc/hosts.deny is owned by root:root",
			Check: func(_ models.SecurityInfo, _ models.KernelSecurityInfo) models.CISResult {
				return checkFileOwnerRootRoot(ruleByID("6.1.28"), "/etc/hosts.deny", "chown root:root /etc/hosts.deny")
			}},
		{ID: "6.1.29", Framework: cisBenchCIS, Level: 1, Section: cisCatFiles,
			Description: "Ensure /etc/resolv.conf permissions are configured (644 or more restrictive)",
			Check: func(_ models.SecurityInfo, _ models.KernelSecurityInfo) models.CISResult {
				r := ruleByID("6.1.29")
				return checkFilePerm(r, "/etc/resolv.conf", 0o644, "chmod 644 /etc/resolv.conf")
			}},
		{ID: "6.1.30", Framework: cisBenchCIS, Level: 1, Section: cisCatFiles,
			Description: "Ensure /etc/resolv.conf is owned by root:root",
			Check: func(_ models.SecurityInfo, _ models.KernelSecurityInfo) models.CISResult {
				return checkFileOwnerRootRoot(ruleByID("6.1.30"), "/etc/resolv.conf", "chown root:root /etc/resolv.conf")
			}},
		{ID: "6.1.31", Framework: cisBenchCIS, Level: 1, Section: cisCatFiles,
			Description: "Ensure /etc/sysctl.conf permissions are configured (600 or more restrictive)",
			Check: func(_ models.SecurityInfo, _ models.KernelSecurityInfo) models.CISResult {
				r := ruleByID("6.1.31")
				return checkFilePerm(r, "/etc/sysctl.conf", 0o600, "chmod 600 /etc/sysctl.conf")
			}},
		{ID: "6.1.32", Framework: cisBenchCIS, Level: 1, Section: cisCatFiles,
			Description: "Ensure /etc/sysctl.conf is owned by root:root",
			Check: func(_ models.SecurityInfo, _ models.KernelSecurityInfo) models.CISResult {
				return checkFileOwnerRootRoot(ruleByID("6.1.32"), "/etc/sysctl.conf", "chown root:root /etc/sysctl.conf")
			}},
		{ID: "6.1.33", Framework: cisBenchCIS, Level: 1, Section: cisCatFiles,
			Description: "Ensure /etc/environment permissions are 644 or stricter",
			Check: func(_ models.SecurityInfo, _ models.KernelSecurityInfo) models.CISResult {
				r := ruleByID("6.1.33")
				return checkFilePerm(r, etcEnvironmentPath, 0o644, "chmod 644 /etc/environment")
			}},
		{ID: "6.1.34", Framework: cisBenchCIS, Level: 1, Section: cisCatFiles,
			Description: "Ensure /etc/environment is owned by root:root",
			Check: func(_ models.SecurityInfo, _ models.KernelSecurityInfo) models.CISResult {
				return checkFileOwnerRootRoot(ruleByID("6.1.34"), etcEnvironmentPath, "chown root:root /etc/environment")
			}},
		{ID: "6.1.35", Framework: cisBenchCIS, Level: 1, Section: cisCatFiles,
			Description: "Ensure /etc/profile permissions are 644 or stricter",
			Check: func(_ models.SecurityInfo, _ models.KernelSecurityInfo) models.CISResult {
				r := ruleByID("6.1.35")
				return checkFilePerm(r, etcProfilePath, 0o644, "chmod 644 /etc/profile")
			}},
		{ID: "6.1.36", Framework: cisBenchCIS, Level: 1, Section: cisCatFiles,
			Description: "Ensure /etc/profile is owned by root:root",
			Check: func(_ models.SecurityInfo, _ models.KernelSecurityInfo) models.CISResult {
				return checkFileOwnerRootRoot(ruleByID("6.1.36"), etcProfilePath, "chown root:root /etc/profile")
			}},
		{ID: "6.1.37", Framework: cisBenchCIS, Level: 1, Section: cisCatFiles,
			Description: "Ensure /etc/login.defs permissions are 644 or stricter",
			Check: func(_ models.SecurityInfo, _ models.KernelSecurityInfo) models.CISResult {
				r := ruleByID("6.1.37")
				return checkFilePerm(r, loginDefsPath, 0o644, "chmod 644 /etc/login.defs")
			}},
		{ID: "6.1.38", Framework: cisBenchCIS, Level: 1, Section: cisCatFiles,
			Description: "Ensure /etc/login.defs is owned by root:root",
			Check: func(_ models.SecurityInfo, _ models.KernelSecurityInfo) models.CISResult {
				return checkFileOwnerRootRoot(ruleByID("6.1.38"), loginDefsPath, "chown root:root /etc/login.defs")
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
				var shadowUnreadable bool
				for _, path := range legacyNISPaths {
					data, err := os.ReadFile(path) // #nosec G304
					if err != nil {
						if strings.Contains(path, "shadow") {
							shadowUnreadable = true
						}
						continue
					}
					for line := range strings.SplitSeq(string(data), "\n") {
						if strings.HasPrefix(strings.TrimSpace(line), "+") {
							return failr(r, fmt.Sprintf("legacy NIS '+' entry in %s", path),
								fmt.Sprintf("remove the '+' line from %s", path))
						}
					}
				}
				if shadowUnreadable {
					return skipr(r, "/etc/shadow not readable — run as root for complete NIS entry check")
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
					return skipr(r, cisSkipPasswdUnreadable)
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
					return skipr(r, cisSkipGroupUnreadable)
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
					return skipr(r, cisSkipPasswdUnreadable)
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
					return skipr(r, cisSkipGroupUnreadable)
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
					return skipr(r, cisSkipPasswdUnreadable)
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

		{ID: "6.2.10", Framework: cisBenchCIS, Level: 1, Section: "Users",
			Description: "Ensure root PATH integrity",
			Check: func(_ models.SecurityInfo, _ models.KernelSecurityInfo) models.CISResult {
				r := ruleByID("6.2.10")
				data, err := os.ReadFile(etcEnvironmentPath) // #nosec G304 -- hardcoded system path
				if err != nil {
					return skipr(r, "could not read /etc/environment — cannot verify root PATH")
				}
				var rootPath string
				for line := range strings.SplitSeq(string(data), "\n") {
					line = strings.TrimSpace(line)
					if rest, ok := strings.CutPrefix(line, "PATH="); ok {
						rootPath = strings.Trim(rest, `"'`)
						break
					}
				}
				if rootPath == "" {
					return skipr(r, "PATH not set in /etc/environment — cannot verify root PATH")
				}
				for component := range strings.SplitSeq(rootPath, ":") {
					if component == "." || component == "" {
						return failr(r, "root PATH contains '.' or empty component — allows command hijacking",
							"remove '.' and empty PATH components from /etc/environment")
					}
					if fi, statErr := os.Stat(component); statErr == nil && fi.Mode()&0002 != 0 { // #nosec G304
						return failr(r,
							fmt.Sprintf("world-writable directory %q in root PATH", component),
							"remove world-writable directories from PATH in /etc/environment")
					}
				}
				return pass(r)
			}},

		{ID: "6.2.11", Framework: cisBenchCIS, Level: 1, Section: "Users",
			Description: "Ensure users own their home directories",
			Check: func(_ models.SecurityInfo, _ models.KernelSecurityInfo) models.CISResult {
				r := ruleByID("6.2.11")
				data, err := os.ReadFile(etcPasswdPath) // #nosec G304 -- hardcoded system path
				if err != nil {
					return skipr(r, cisSkipPasswdUnreadable)
				}
				var violations []string
				for line := range strings.SplitSeq(string(data), "\n") {
					line = strings.TrimSpace(line)
					if line == "" || strings.HasPrefix(line, "#") {
						continue
					}
					fields := strings.SplitN(line, ":", 7)
					if len(fields) < 6 {
						continue
					}
					uid, atoiErr := strconv.Atoi(fields[2])
					if atoiErr != nil || uid < 1000 || uid >= 65534 {
						continue
					}
					homeDir := fields[5]
					if homeDir == "" || homeDir == cisHomeNonexistent || homeDir == cisHomeDevNull {
						continue
					}
					fi, statErr := os.Lstat(homeDir) // #nosec G304 -- from /etc/passwd, not user input
					if statErr != nil {
						continue
					}
					st, ok := fi.Sys().(*syscall.Stat_t)
					if !ok {
						continue
					}
					if st.Uid != uint32(uid) {
						violations = append(violations,
							fmt.Sprintf("%s (home=%s, owner uid=%d, expected=%d)", fields[0], homeDir, st.Uid, uid))
					}
				}
				if len(violations) > 0 {
					shown := violations[:min(3, len(violations))]
					return failr(r,
						fmt.Sprintf("%d home dir(s) not owned by user: %s", len(violations), strings.Join(shown, "; ")),
						"chown <user>:<user> <home> for each affected account")
				}
				return pass(r)
			}},

		{ID: "6.2.12", Framework: cisBenchCIS, Level: 1, Section: "Users",
			Description: "Ensure users' home directories permissions are 750 or more restrictive",
			Check: func(_ models.SecurityInfo, _ models.KernelSecurityInfo) models.CISResult {
				r := ruleByID("6.2.12")
				data, err := os.ReadFile(etcPasswdPath) // #nosec G304 -- hardcoded system path
				if err != nil {
					return skipr(r, cisSkipPasswdUnreadable)
				}
				var violations []string
				for line := range strings.SplitSeq(string(data), "\n") {
					line = strings.TrimSpace(line)
					if line == "" || strings.HasPrefix(line, "#") {
						continue
					}
					fields := strings.SplitN(line, ":", 7)
					if len(fields) < 6 {
						continue
					}
					uid, atoiErr := strconv.Atoi(fields[2])
					if atoiErr != nil || uid < 1000 || uid >= 65534 {
						continue
					}
					homeDir := fields[5]
					if homeDir == "" || homeDir == cisHomeNonexistent || homeDir == cisHomeDevNull {
						continue
					}
					fi, statErr := os.Lstat(homeDir) // #nosec G304 -- from /etc/passwd, not user input
					if statErr != nil {
						continue
					}
					if perm := fi.Mode().Perm(); perm&0022 != 0 {
						violations = append(violations,
							fmt.Sprintf("%s (home=%s, mode=%04o)", fields[0], homeDir, perm))
					}
				}
				if len(violations) > 0 {
					shown := violations[:min(3, len(violations))]
					return failr(r,
						fmt.Sprintf("%d home dir(s) are group/world writable: %s", len(violations), strings.Join(shown, "; ")),
						"chmod g-w,o-w <home> for each affected account")
				}
				return pass(r)
			}},

		{ID: "6.2.13", Framework: cisBenchCIS, Level: 1, Section: "Users",
			Description: "Ensure users' dot files are not world-writable",
			Check: func(_ models.SecurityInfo, _ models.KernelSecurityInfo) models.CISResult {
				r := ruleByID("6.2.13")
				data, err := os.ReadFile(etcPasswdPath) // #nosec G304 -- hardcoded system path
				if err != nil {
					return skipr(r, cisSkipPasswdUnreadable)
				}
				var violations []string
				checked := 0
				for line := range strings.SplitSeq(string(data), "\n") {
					line = strings.TrimSpace(line)
					if line == "" || strings.HasPrefix(line, "#") {
						continue
					}
					fields := strings.SplitN(line, ":", 7)
					if len(fields) < 6 {
						continue
					}
					uid, atoiErr := strconv.Atoi(fields[2])
					if atoiErr != nil || uid < 1000 || uid >= 65534 {
						continue
					}
					homeDir := fields[5]
					if homeDir == "" || homeDir == cisHomeNonexistent || homeDir == cisHomeDevNull {
						continue
					}
					entries, rdErr := os.ReadDir(homeDir) // #nosec G304 -- path from /etc/passwd
					if rdErr != nil {
						continue
					}
					checked++
					for _, e := range entries {
						if !strings.HasPrefix(e.Name(), ".") || e.IsDir() {
							continue
						}
						fi, infoErr := e.Info()
						if infoErr != nil {
							continue
						}
						if fi.Mode().Perm()&0002 != 0 {
							violations = append(violations,
								fmt.Sprintf("%s/%s (%04o)", homeDir, e.Name(), fi.Mode().Perm()))
						}
					}
				}
				if checked == 0 {
					return skipr(r, "could not read any home directories — run as root for complete check")
				}
				if len(violations) > 0 {
					shown := violations[:min(3, len(violations))]
					return failr(r,
						fmt.Sprintf("%d dot file(s) are world-writable: %s", len(violations), strings.Join(shown, "; ")),
						"chmod o-w <file> for each world-writable dot file in home directories")
				}
				return pass(r)
			}},

		{ID: "6.2.14", Framework: cisBenchCIS, Level: 1, Section: "Users",
			Description: "Ensure no users have .forward files",
			Check: func(_ models.SecurityInfo, _ models.KernelSecurityInfo) models.CISResult {
				r := ruleByID("6.2.14")
				data, err := os.ReadFile(etcPasswdPath) // #nosec G304 -- hardcoded system path
				if err != nil {
					return skipr(r, cisSkipPasswdUnreadable)
				}
				var found []string
				accessible := 0
				for line := range strings.SplitSeq(string(data), "\n") {
					line = strings.TrimSpace(line)
					if line == "" || strings.HasPrefix(line, "#") {
						continue
					}
					fields := strings.SplitN(line, ":", 7)
					if len(fields) < 6 {
						continue
					}
					uid, atoiErr := strconv.Atoi(fields[2])
					if atoiErr != nil || uid < 1000 || uid >= 65534 {
						continue
					}
					homeDir := fields[5]
					if homeDir == "" || homeDir == cisHomeNonexistent || homeDir == cisHomeDevNull {
						continue
					}
					if _, statErr := os.Stat(homeDir); statErr != nil { // #nosec G304
						continue // home dir not accessible
					}
					accessible++
					fwd := filepath.Join(homeDir, ".forward")
					if _, statErr := os.Stat(fwd); statErr == nil { // #nosec G304
						found = append(found, fmt.Sprintf("%s (%s)", fields[0], fwd))
					}
				}
				if accessible == 0 {
					return skipr(r, cisSkipHomeDirsUnreadable)
				}
				if len(found) > 0 {
					shown := found[:min(3, len(found))]
					return failr(r,
						fmt.Sprintf("%d user(s) have .forward files: %s", len(found), strings.Join(shown, "; ")),
						"rm ~/.forward for each affected user — .forward files can be abused for mail relay")
				}
				return pass(r)
			}},

		{ID: "6.2.15", Framework: cisBenchCIS, Level: 1, Section: "Users",
			Description: "Ensure no users have .netrc files",
			Check: func(_ models.SecurityInfo, _ models.KernelSecurityInfo) models.CISResult {
				r := ruleByID("6.2.15")
				data, err := os.ReadFile(etcPasswdPath) // #nosec G304 -- hardcoded system path
				if err != nil {
					return skipr(r, cisSkipPasswdUnreadable)
				}
				var found []string
				accessible := 0
				for line := range strings.SplitSeq(string(data), "\n") {
					line = strings.TrimSpace(line)
					if line == "" || strings.HasPrefix(line, "#") {
						continue
					}
					fields := strings.SplitN(line, ":", 7)
					if len(fields) < 6 {
						continue
					}
					uid, atoiErr := strconv.Atoi(fields[2])
					if atoiErr != nil || uid < 1000 || uid >= 65534 {
						continue
					}
					homeDir := fields[5]
					if homeDir == "" || homeDir == cisHomeNonexistent || homeDir == cisHomeDevNull {
						continue
					}
					if _, statErr := os.Stat(homeDir); statErr != nil { // #nosec G304
						continue // home dir not accessible
					}
					accessible++
					netrc := filepath.Join(homeDir, ".netrc")
					if _, statErr := os.Stat(netrc); statErr == nil { // #nosec G304
						found = append(found, fmt.Sprintf("%s (%s)", fields[0], netrc))
					}
				}
				if accessible == 0 {
					return skipr(r, cisSkipHomeDirsUnreadable)
				}
				if len(found) > 0 {
					shown := found[:min(3, len(found))]
					return failr(r,
						fmt.Sprintf("%d user(s) have .netrc files: %s", len(found), strings.Join(shown, "; ")),
						"rm ~/.netrc for each affected user — .netrc stores plaintext FTP credentials")
				}
				return pass(r)
			}},

		{ID: "6.2.16", Framework: cisBenchCIS, Level: 1, Section: "Users",
			Description: "Ensure no users have .rhosts files",
			Check: func(_ models.SecurityInfo, _ models.KernelSecurityInfo) models.CISResult {
				r := ruleByID("6.2.16")
				data, err := os.ReadFile(etcPasswdPath) // #nosec G304 -- hardcoded system path
				if err != nil {
					return skipr(r, cisSkipPasswdUnreadable)
				}
				var found []string
				accessible := 0
				for line := range strings.SplitSeq(string(data), "\n") {
					line = strings.TrimSpace(line)
					if line == "" || strings.HasPrefix(line, "#") {
						continue
					}
					fields := strings.SplitN(line, ":", 7)
					if len(fields) < 6 {
						continue
					}
					uid, atoiErr := strconv.Atoi(fields[2])
					if atoiErr != nil || uid < 1000 || uid >= 65534 {
						continue
					}
					homeDir := fields[5]
					if homeDir == "" || homeDir == cisHomeNonexistent || homeDir == cisHomeDevNull {
						continue
					}
					if _, statErr := os.Stat(homeDir); statErr != nil { // #nosec G304
						continue // home dir not accessible
					}
					accessible++
					rhosts := filepath.Join(homeDir, ".rhosts")
					if _, statErr := os.Stat(rhosts); statErr == nil { // #nosec G304
						found = append(found, fmt.Sprintf("%s (%s)", fields[0], rhosts))
					}
				}
				if accessible == 0 {
					return skipr(r, cisSkipHomeDirsUnreadable)
				}
				if len(found) > 0 {
					shown := found[:min(3, len(found))]
					return failr(r,
						fmt.Sprintf("%d user(s) have .rhosts files: %s", len(found), strings.Join(shown, "; ")),
						"rm ~/.rhosts for each affected user — .rhosts enables passwordless rsh/rlogin (insecure legacy protocol)")
				}
				return pass(r)
			}},

		{ID: "6.2.17", Framework: cisBenchCIS, Level: 1, Section: "Users",
			Description: "Ensure all groups in /etc/passwd exist in /etc/group",
			Check: func(_ models.SecurityInfo, _ models.KernelSecurityInfo) models.CISResult {
				r := ruleByID("6.2.17")
				grpData, err := os.ReadFile(etcGroupPath) // #nosec G304 -- hardcoded system path
				if err != nil {
					return skipr(r, cisSkipGroupUnreadable)
				}
				knownGIDs := make(map[int]bool)
				for line := range strings.SplitSeq(string(grpData), "\n") {
					line = strings.TrimSpace(line)
					if line == "" || strings.HasPrefix(line, "#") {
						continue
					}
					fields := strings.SplitN(line, ":", 4)
					if len(fields) < 3 {
						continue
					}
					gid, atoiErr := strconv.Atoi(fields[2])
					if atoiErr == nil {
						knownGIDs[gid] = true
					}
				}
				pwData, err := os.ReadFile(etcPasswdPath) // #nosec G304 -- hardcoded system path
				if err != nil {
					return skipr(r, cisSkipPasswdUnreadable)
				}
				var missing []string
				for line := range strings.SplitSeq(string(pwData), "\n") {
					line = strings.TrimSpace(line)
					if line == "" || strings.HasPrefix(line, "#") {
						continue
					}
					fields := strings.SplitN(line, ":", 7)
					if len(fields) < 4 {
						continue
					}
					gid, atoiErr := strconv.Atoi(fields[3])
					if atoiErr != nil {
						continue
					}
					if !knownGIDs[gid] {
						missing = append(missing, fmt.Sprintf("%s (GID %d)", fields[0], gid))
					}
				}
				if len(missing) > 0 {
					shown := missing[:min(3, len(missing))]
					return failr(r,
						fmt.Sprintf("%d user(s) reference undefined GID(s): %s", len(missing), strings.Join(shown, "; ")),
						"add the missing group to /etc/group or assign users to an existing group")
				}
				return pass(r)
			}},

		{ID: "6.2.18", Framework: cisBenchCIS, Level: 1, Section: "Users",
			Description: "Ensure the shadow group is empty",
			Check: func(_ models.SecurityInfo, _ models.KernelSecurityInfo) models.CISResult {
				r := ruleByID("6.2.18")
				data, err := os.ReadFile(etcGroupPath) // #nosec G304 -- hardcoded system path
				if err != nil {
					return skipr(r, cisSkipGroupUnreadable)
				}
				for line := range strings.SplitSeq(string(data), "\n") {
					line = strings.TrimSpace(line)
					if line == "" || strings.HasPrefix(line, "#") {
						continue
					}
					fields := strings.SplitN(line, ":", 4)
					if len(fields) < 4 || fields[0] != "shadow" {
						continue
					}
					members := strings.TrimSpace(fields[3])
					if members == "" {
						return pass(r)
					}
					parts := strings.Split(members, ",")
					shown := members
					if len(parts) > 3 {
						shown = strings.Join(parts[:3], ",") + "…"
					}
					return failr(r,
						fmt.Sprintf("shadow group has members: %s", shown),
						"remove all users from the shadow group in /etc/group — membership grants read access to /etc/shadow")
				}
				return pass(r) // shadow group absent — acceptable
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
				if sec.SSHConfigUnreadable {
					return skipr(r, cisSkipSSHConfigUnreadable)
				}
				if sec.SSHClientAliveCountMax != 0 {
					return failr(r,
						fmt.Sprintf("ClientAliveCountMax is %d (must be 0 — no grace retries after idle timeout)", sec.SSHClientAliveCountMax),
						"set ClientAliveCountMax 0 in /etc/ssh/sshd_config")
				}
				return pass(r)
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

		// V-238384: Authentication delay — pam_faildelay ≥ 4 000 000 µs (4 seconds)
		{ID: "V-238384", Framework: cisBenchSTIG, Level: 1, Section: cisCatAuth,
			Description: "The OS must implement a delay of at least 4 seconds between failed logon attempts",
			Check: func(_ models.SecurityInfo, _ models.KernelSecurityInfo) models.CISResult {
				r := ruleByID("V-238384")
				data, err := os.ReadFile(pamCommonAuthPath) // #nosec G304 -- package-level var
				if err != nil {
					return skipr(r, "/etc/pam.d/common-auth not readable")
				}
				for line := range strings.SplitSeq(string(data), "\n") {
					line = strings.TrimSpace(line)
					if strings.HasPrefix(line, "#") || !strings.Contains(line, "pam_faildelay.so") {
						continue
					}
					for field := range strings.FieldsSeq(line) {
						rest, ok := strings.CutPrefix(field, "delay=")
						if !ok {
							continue
						}
						n, parseErr := strconv.Atoi(rest)
						if parseErr != nil {
							continue
						}
						if n < 4000000 {
							return failr(r,
								fmt.Sprintf("pam_faildelay delay=%d µs is below STIG minimum of 4 000 000 µs (4 s)", n),
								"set 'delay=4000000' on the pam_faildelay.so line in /etc/pam.d/common-auth")
						}
						return pass(r)
					}
				}
				return failr(r, "pam_faildelay.so not configured in /etc/pam.d/common-auth",
					"add 'auth optional pam_faildelay.so delay=4000000' to /etc/pam.d/common-auth")
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

// apport paths for rule 1.5.3 (automatic error reporting disabled).
var apportBinPaths = []string{"/usr/share/apport/apport", "/usr/bin/apport-cli"}

// apportDefaultPath is the apport enabled/disabled flag file.
var apportDefaultPath = "/etc/default/apport"

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
var auditRulesDPath = "/etc/audit/rules.d"
var auditRulesFilePath = "/etc/audit/audit.rules"

// auditdConfPath for auditd configuration checks (4.1.1.1–4.1.1.3).
var auditdConfPath = "/etc/audit/auditd.conf"

// procCmdlinePath for kernel command-line parameter checks (4.1.1.4).
var procCmdlinePath = "/proc/cmdline"

// nisServerBinPaths for NIS server check (2.3.16).
var nisServerBinPaths = []string{"/usr/sbin/ypserv", "/usr/lib/yp/ypserv"}

// sshHostKeyDir for SSH host key permission checks (5.2.3, 5.2.4).
var sshHostKeyDir = "/etc/ssh"

// journaldConfPath and journaldConfDPath for journald config checks (4.2.2–4.2.2.3).
var journaldConfPath = "/etc/systemd/journald.conf"
var journaldConfDPath = "/etc/systemd/journald.conf.d"

// securettyPath for root-login restriction check (5.5.1).
var securettyPath = "/etc/securetty"

// pamSuPath for su-command restriction check (5.5.2).
var pamSuPath = "/etc/pam.d/su"

// pwqualityConfPath for pam_pwquality password complexity check (5.4.9).
var pwqualityConfPath = "/etc/security/pwquality.conf" //nolint:gosec // G101 false positive — path, not credential

// faillockConfPath for pam_faillock account lockout check (5.4.10).
var faillockConfPath = "/etc/security/faillock.conf"

// pamCommonAuthPath for PAM account lockout fallback check (5.4.10).
var pamCommonAuthPath = "/etc/pam.d/common-auth"

// pamCommonPasswordPath for password hashing (5.4.11) and reuse (5.4.12) checks.
var pamCommonPasswordPath = "/etc/pam.d/common-password" //nolint:gosec // G101 false positive — path, not credential

// pamDPath is the PAM configuration directory scanned by rule 5.4.17 (nullok check).
// Package-level var for test injection.
var pamDPath = "/etc/pam.d"

// etcProfilePath, etcProfileDPath, etcBashrcPath for umask (5.5.3) and TMOUT (5.5.4) checks.
var etcProfilePath = "/etc/profile"
var etcProfileDPath = "/etc/profile.d"
var etcBashrcPath = "/etc/bash.bashrc"

// rsyslogConfPath and rsyslogConfDPath for rsyslog remote-logging check (4.2.3).
var rsyslogConfPath = "/etc/rsyslog.conf"
var rsyslogConfDPath = "/etc/rsyslog.d"

// varLogPath for log file permissions check (4.2.7).
var varLogPath = "/var/log"

// sysctl paths for kernel hardening GE checks (1.5.8-1.5.10).
var perfEventParanoidPath = "/proc/sys/kernel/perf_event_paranoid"
var kptrRestrictPath = "/proc/sys/kernel/kptr_restrict"
var yamaPtraceScopePath = "/proc/sys/kernel/yama/ptrace_scope"

// sysctl paths for BPF JIT + mmap checks (1.5.11-1.5.12).
var bpfJitHardenPath = "/proc/sys/net/core/bpf_jit_harden"
var mmapMinAddrPath = "/proc/sys/vm/mmap_min_addr"

// sysctl paths for SysRq and core dump PID (1.5.14-1.5.15).
var sysrqPath = "/proc/sys/kernel/sysrq"
var coreUsesPidPath = "/proc/sys/kernel/core_uses_pid"

// sysctl paths for sticky-directory file creation protection (1.5.16-1.5.17).
var protectedRegularPath = "/proc/sys/fs/protected_regular"
var protectedFifosPath = "/proc/sys/fs/protected_fifos"

// sysctl path for unprivileged BPF restriction (1.5.18).
var unprivilegedBpfDisabledPath = "/proc/sys/kernel/unprivileged_bpf_disabled"

// apparmorParserPaths: candidates for the apparmor_parser binary (1.6.1).
var apparmorParserPaths = []string{"/usr/sbin/apparmor_parser", "/sbin/apparmor_parser"}

// grubDefaultPath: GRUB default configuration for bootloader checks (1.6.2).
var grubDefaultPath = "/etc/default/grub"

// apparmorProfilesPath: AppArmor loaded-profile list in the security filesystem (1.6.3, 1.6.4).
var apparmorProfilesPath = "/sys/kernel/security/apparmor/profiles"

// etcEnvironmentPath: system-wide environment file checked for root PATH integrity (6.2.10).
var etcEnvironmentPath = "/etc/environment"

// cronWantsPaths: systemd wants-directory symlinks that indicate cron is enabled (5.1.1).
var cronWantsPaths = []string{
	"/etc/systemd/system/multi-user.target.wants/cron.service",
	"/etc/systemd/system/multi-user.target.wants/crond.service",
}

// debianVersionPath is the Debian/Ubuntu family indicator; gates Debian-specific rules.
var debianVersionPath = "/etc/debian_version"

// aptConfDPath for APT configuration directory (unauthenticated package check 1.2.3).
var aptConfDPath = "/etc/apt/apt.conf.d"

// unattendedUpgradesBinPaths for automatic security updates check (1.2.4).
var unattendedUpgradesBinPaths = []string{"/usr/bin/unattended-upgrade", "/usr/bin/unattended-upgrades"}

// ufwBinPaths for ufw binary presence checks (3.5.1.1, 3.5.1.3).
var ufwBinPaths = []string{"/usr/sbin/ufw", "/sbin/ufw"}

// netfilterPersistentPaths for iptables-persistent conflict check (3.5.1.2).
var netfilterPersistentPaths = []string{
	"/lib/systemd/system/netfilter-persistent.service",
	"/etc/init.d/iptables-persistent",
}

// ufwWantsPaths for ufw service enabled check (3.5.1.3).
var ufwWantsPaths = []string{
	"/etc/systemd/system/multi-user.target.wants/ufw.service",
	"/run/systemd/generator.late/multi-user.target.wants/ufw.service",
}

// ufwDefaultPath: ufw default policy config (3.5.1.7, 3.5.1.5).
var ufwDefaultPath = "/etc/default/ufw"

// ufwBeforeRulesPath and ufwBefore6RulesPath for UFW loopback check (3.5.1.4).
var ufwBeforeRulesPath = "/etc/ufw/before.rules"
var ufwBefore6RulesPath = "/etc/ufw/before6.rules"

// aptSourcesListPath and aptSourcesListDPath for package repo check (1.2.1).
var aptSourcesListPath = "/etc/apt/sources.list"
var aptSourcesListDPath = "/etc/apt/sources.list.d"

// aptTrustedGpgPath, aptTrustedGpgDPath, aptKeyringsPath for GPG key check (1.2.2).
var aptTrustedGpgPath = "/etc/apt/trusted.gpg"
var aptTrustedGpgDPath = "/etc/apt/trusted.gpg.d"
var aptKeyringsPath = "/etc/apt/keyrings"

// sysClassNetPath for wireless interface check (3.6.1).
var sysClassNetPath = "/sys/class/net"

// ufwUserRulesPath for UFW outbound connections check (3.5.1.5).
var ufwUserRulesPath = "/etc/ufw/user.rules"

// ldapClientBinPaths for LDAP client check (2.2.5).
var ldapClientBinPaths = []string{
	"/usr/bin/ldapsearch",
	"/usr/bin/ldapadd",
	"/usr/bin/ldapmodify",
}

// mtaBinPaths for MTA local-only mode check (2.3.14).
var mtaBinPaths = []string{
	"/usr/sbin/postfix",
	"/usr/lib/postfix/sbin/master",
	"/usr/sbin/sendmail",
}

// postfixMainCfPath for MTA local-only mode check (2.3.14).
var postfixMainCfPath = "/etc/postfix/main.cf"

// rsyncBinPaths for rsync service check (2.3.15).
var rsyncBinPaths = []string{"/usr/bin/rsync"}

// rsyncWantsPaths: systemd wants-directory symlinks for rsync daemon (2.3.15).
var rsyncWantsPaths = []string{
	"/etc/systemd/system/multi-user.target.wants/rsync.service",
	"/run/systemd/generator.late/multi-user.target.wants/rsync.service",
}

// rsyncDefaultPath: Debian/Ubuntu rsync daemon init default file (2.3.15).
var rsyncDefaultPath = "/etc/default/rsync"

// logrotateConfPath and logrotateConfDPath for logrotate config check (4.3.1).
var logrotateConfPath = "/etc/logrotate.conf"
var logrotateConfDPath = "/etc/logrotate.d"

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
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}
		lineFields := strings.Fields(trimmed)
		if len(lineFields) == 0 || lineFields[0] != field {
			continue
		}
		// Matched field name exactly — now check that a value is present.
		if len(lineFields) < 2 {
			return failr(r, fmt.Sprintf("%s has no value", field), failFix)
		}
		days := 0
		fmt.Sscanf(lineFields[1], "%d", &days) //nolint:errcheck
		if fails(days) {
			return failr(r, fmt.Sprintf(failFmt, days), failFix)
		}
		return pass(r)
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

// checkSysctlGE reads a /proc/sys file and verifies the integer value is >= minVal.
// Returns SKIP when the file is missing or non-integer, PASS when the value is
// sufficient, FAIL when the value is below the minimum.
func checkSysctlGE(r Rule, path string, minVal int, finding, fix string) models.CISResult {
	data, err := os.ReadFile(path) // #nosec G304 -- hardcoded /proc paths
	if err != nil {
		return skipr(r, fmt.Sprintf("could not read %s", path))
	}
	v, convErr := strconv.Atoi(strings.TrimSpace(string(data)))
	if convErr != nil {
		return skipr(r, fmt.Sprintf("%s: non-integer value %q", path, strings.TrimSpace(string(data))))
	}
	if v < minVal {
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

// checkRemovableMediaOption checks that all heuristically-detected removable
// media mounts include the given option. Removable media is identified as block
// devices (sd* or sr*) mounted under /media/ or /mnt/. If no such mounts exist
// the check passes — compliant by absence.
func checkRemovableMediaOption(r Rule, option string) models.CISResult {
	data, err := os.ReadFile(procMountsPath) //nolint:gosec // package-level var
	if err != nil {
		return skipr(r, fmt.Sprintf("could not read %s", procMountsPath))
	}
	for line := range strings.SplitSeq(string(data), "\n") {
		fields := strings.Fields(line)
		if len(fields) < 4 {
			continue
		}
		dev, mp := fields[0], fields[1]
		base := filepath.Base(dev)
		isRemovable := (strings.HasPrefix(base, "sd") || strings.HasPrefix(base, "sr")) &&
			(strings.HasPrefix(mp, "/media/") || strings.HasPrefix(mp, "/mnt/"))
		if !isRemovable {
			continue
		}
		for opt := range strings.SplitSeq(fields[3], ",") {
			if opt == option {
				goto nextMount
			}
		}
		return failr(r,
			fmt.Sprintf("removable media %s (%s) lacks %q option", mp, dev, option),
			fmt.Sprintf("add '%s' to mount options in /etc/fstab for removable media", option))
	nextMount:
	}
	return pass(r)
}

// checkAuditRule verifies that audit configuration files contain at least one
// line matching any of patterns. It reads all *.rules files in auditRulesDPath
// and auditRulesFilePath. Returns SKIP when no audit rule files are readable
// (auditd not installed / non-Linux).
// auditLineMatchesPattern checks if line contains pattern at a word boundary.
// A plain strings.Contains is insufficient because "-w /etc/passwd" would also
// match "-w /etc/passwd-". We require that the character immediately following
// the pattern (if any) is a space, tab, comma (for comma-separated syscall lists),
// or end of string.
func auditLineMatchesPattern(line, pattern string) bool {
	idx := strings.Index(line, pattern)
	if idx < 0 {
		return false
	}
	after := idx + len(pattern)
	if after < len(line) {
		next := line[after]
		if next != ' ' && next != '\t' && next != ',' {
			return false
		}
	}
	return true
}

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

	// ALL patterns must be found — OR semantics would pass a rule that only
	// partially covers the required watch set (e.g. /etc/passwd but not /etc/shadow).
	for _, pattern := range patterns {
		found := false
		for _, line := range lines {
			trimmed := strings.TrimSpace(line)
			if trimmed == "" || strings.HasPrefix(trimmed, "#") {
				continue
			}
			if auditLineMatchesPattern(trimmed, pattern) {
				found = true
				break
			}
		}
		if !found {
			return failr(r, fmt.Sprintf("audit rule not found: %s", pattern), fix)
		}
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

		if refs := NIS2Refs(rule.ID); len(refs) > 0 {
			result.NIS2Refs = refs
		}
		if refs := BSIRefs(rule.ID); len(refs) > 0 {
			result.BSIRefs = refs
		}

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
