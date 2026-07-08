package analysis

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/keyorixhq/dashdiag/internal/baseline"
	"github.com/keyorixhq/dashdiag/internal/models"
)

// SecurityConcernCount returns the number of WARN/CRIT security insights that
// checkSecurity raises for sec. It is the single source of truth for the
// standalone `dsd security` verdict so it CANNOT diverge from `dsd health` (the
// sibling-divergence class — BUG-072: the old hand-tallied countSecurityIssues
// omitted StrictModes/PermitEmptyPasswords/weak-MACs/password-never-expires that
// checkSecurity flags). INFO-level findings are not concerns and aren't counted.
func SecurityConcernCount(sec models.SecurityInfo) int {
	n := 0
	for _, ins := range checkSecurity(sec) {
		if ins.Level == "WARN" || ins.Level == "CRIT" {
			n++
		}
	}
	return n
}

// checkSecurity is the flat dispatcher for the `dsd security`/`dsd health`
// hardening checks. Each sub-check below covers one theme (SSH config, network
// exposure, privilege-escalation vectors, distro-specific compliance tooling,
// macOS) and is independent of the others — split out of a single ~500-line
// function for readability (was `//nolint:funlen,cyclop`, see git history).
// Order of appends must stay stable: `SecurityConcernCount`/tests don't depend
// on insight order, but callers that print top-N assume append order.
func checkSecurity(sec models.SecurityInfo) []models.Insight {
	out := make([]models.Insight, 0, 14) // one slot per sub-check below; grows past this on a noisy host
	out = append(out, checkSecurityAuditGaps(sec)...)
	out = append(out, checkSSHHardening(sec)...)
	out = append(out, checkFailedLoginAttempts(sec)...)
	out = append(out, checkNetworkExposure(sec)...)
	out = append(out, checkPrivilegeEscalationVectors(sec)...)
	out = append(out, checkSecuritySELinuxDenials(sec)...)
	out = append(out, checkAppArmorDenials(sec)...)
	out = append(out, checkPAMFailures(sec)...)
	out = append(out, checkRHELSecurityHardening(sec)...)
	out = append(out, checkSUSESecurityHardening(sec)...)
	out = append(out, checkEmptyPasswords(sec)...)
	out = append(out, checkStalePasswords(sec)...)
	out = append(out, checkWorldWritable(sec)...)
	out = append(out, checkMacOSHardening(sec)...)
	return out
}

// checkSecurityAuditGaps surfaces the root-gated reads that silently limit the
// rest of checkSecurity's coverage (INFO only — never raises the verdict), so a
// non-root run reads as "audited, clean" rather than "clean because we didn't look".
func checkSecurityAuditGaps(sec models.SecurityInfo) []models.Insight {
	var out []models.Insight

	if sec.NeedsRoot {
		out = append(out, insight("INFO", "Hardening",
			"some checks limited — run as root for port process names, failed logins, and SELinux audit log",
			nil,
		))
	}

	// The sshd config existed but couldn't be read (mode 600, non-root, and
	// `sshd -T` also needs root). The SSH directives below default to their secure
	// values, so without this the host would read as SSH-hardened having audited
	// nothing — a false-OK on a security check. Surface it; INFO doesn't raise the
	// verdict.
	if sec.SSHConfigUnreadable && sec.SSHAuditSource == "" {
		out = append(out, insight("INFO", "Hardening",
			"SSH config present but not readable — sshd settings (root login, password auth, ciphers) were NOT audited",
			[]string{"to audit: re-run as root (sudo dsd security)"},
		))
	}

	// /etc/shadow couldn't be read (non-root), so the empty/never-expiring-password
	// audits read nothing — an empty-password account would otherwise pass as clean.
	if sec.ShadowUnreadable {
		out = append(out, insight("INFO", "Hardening",
			"/etc/shadow not readable — empty/never-expiring password accounts were NOT audited",
			[]string{"to audit: re-run as root (sudo dsd security)"},
		))
	}

	// Neither journald nor the auth-log file could be read at all — the
	// failed-login/PAM checks below silently see zero, indistinguishable from
	// a genuinely clean host, unless this is surfaced explicitly.
	if sec.FailedLoginsUnreadable {
		out = append(out, insight("INFO", "Hardening",
			"SSH auth log not readable — failed-login/brute-force attempts were NOT audited",
			[]string{"to audit: re-run as root (sudo dsd security)"},
		))
	}

	if sec.PAMFailuresUnreadable {
		out = append(out, insight("INFO", "Hardening",
			"PAM auth log not readable — su/sudo/login/cron authentication failures were NOT audited",
			[]string{"to audit: re-run as root (sudo dsd security)"},
		))
	}

	return out
}

// checkSSHHardening covers sshd_config directives (root login, password auth,
// weak algorithms, idle timeout, etc.) — a flat list of independent conditions.
func checkSSHHardening(sec models.SecurityInfo) []models.Insight { //nolint:funlen // flat list of independent sshd_config conditions; splitting would harm readability
	var out []models.Insight

	// SSH misconfigurations
	if sec.SSHPermitRoot {
		switch {
		case sec.IsOffensiveDistro:
			// On offensive/pentest distros (Kali, Parrot), root SSH is intentional.
			// Downgrade to INFO with a note rather than CRIT.
			out = append(out, insight("INFO", "Hardening",
				"SSH root login enabled — expected on offensive security distro (Kali/Parrot)",
				nil,
			))
		case sec.IsPVE:
			// Proxmox VE requires root SSH for cluster management — not a
			// misconfiguration. Downgrade to INFO (see BUG-018).
			out = append(out, insight("INFO", "Hardening",
				"Root SSH login enabled — required for PVE management. Restrict to key-based auth if not already done.",
				[]string{"to fix: set PasswordAuthentication no in /etc/ssh/sshd_config"},
			))
		default:
			out = append(out, insight("CRIT", "Hardening",
				"SSH permits root login",
				[]string{"to fix: set PermitRootLogin no in /etc/ssh/sshd_config", "to fix: systemctl restart sshd"},
			))
		}
	}
	if sec.SSHPasswordAuth {
		if sec.IsOffensiveDistro {
			out = append(out, insight("INFO", "Hardening",
				"SSH password auth enabled — expected on offensive security distro (Kali/Parrot)",
				nil,
			))
		} else {
			out = append(out, insight("WARN", "Hardening",
				"SSH allows password authentication — key-based auth recommended",
				[]string{"to fix: set PasswordAuthentication no in /etc/ssh/sshd_config"},
			))
		}
	}

	// ── SSH config audit — additional CIS checks ──────────────────────────

	// Protocol 1 is cryptographically broken (DES, 1990s-era)
	if sec.SSHProtocol1 {
		out = append(out, insight("CRIT", "Hardening",
			"SSH Protocol 1 is enabled — cryptographically broken, remove from sshd_config",
			[]string{
				"to fix: remove or comment out 'Protocol' line in /etc/ssh/sshd_config",
				"note: modern OpenSSH only supports Protocol 2 — this line has no effect unless very old",
			},
		))
	}

	// PermitEmptyPasswords — allows login with no password at all
	if sec.SSHPermitEmptyPwd {
		out = append(out, insight("CRIT", "Hardening",
			"SSH allows empty passwords — any account with no password is remotely accessible",
			[]string{
				"to fix: set PermitEmptyPasswords no in /etc/ssh/sshd_config",
				"to fix: systemctl restart sshd",
				"to audit: awk -F: '($2==\"\"){print $1}' /etc/shadow",
			},
		))
	}

	// StrictModes disabled — sshd won't check file permissions on ~/.ssh
	// This allows world-writable authorized_keys to be used (privilege escalation vector)
	if !sec.SSHStrictModes {
		out = append(out, insight("WARN", "Hardening",
			"SSH StrictModes disabled — sshd will not check ~/.ssh file permissions",
			[]string{
				"to fix: set StrictModes yes in /etc/ssh/sshd_config",
				"note: without StrictModes, world-writable authorized_keys files are accepted",
			},
		))
	}

	// MaxAuthTries > 6 — too many attempts before disconnect (brute force risk)
	// CIS benchmark recommends ≤ 4; we warn at > 6 to avoid noise on defaults
	if sec.SSHMaxAuthTries > 6 {
		out = append(out, insight("WARN", "Hardening",
			fmt.Sprintf("SSH MaxAuthTries is %d — reduce to 4 or fewer to limit brute force attempts", sec.SSHMaxAuthTries),
			[]string{
				"to fix: set MaxAuthTries 4 in /etc/ssh/sshd_config",
				"to fix: systemctl restart sshd",
			},
		))
	}

	// LoginGraceTime > 60s — long window for unauthenticated connections (DoS risk)
	// Default is 120s in older OpenSSH; CIS recommends ≤ 60s
	if sec.SSHLoginGraceTime > 60 {
		out = append(out, insight("INFO", "Hardening",
			fmt.Sprintf("SSH LoginGraceTime is %ds — recommend ≤60s to limit unauthenticated connection window",
				sec.SSHLoginGraceTime),
			[]string{
				"to fix: set LoginGraceTime 60 in /etc/ssh/sshd_config",
				"to fix: systemctl restart sshd",
			},
		))
	}

	// X11Forwarding — attack surface on servers, should be off
	if sec.SSHX11Forwarding && !sec.IsOffensiveDistro {
		out = append(out, insight("INFO", "Hardening",
			"SSH X11Forwarding enabled — unnecessary on servers, increases attack surface",
			[]string{
				"to fix: set X11Forwarding no in /etc/ssh/sshd_config",
				"note: only needed if users require GUI applications over SSH",
			},
		))
	}

	// AgentForwarding — allows attackers with root on a jump host to use your keys
	if sec.SSHAgentForwarding && !sec.IsOffensiveDistro {
		out = append(out, insight("INFO", "Hardening",
			"SSH AgentForwarding enabled — if this server is compromised, agent keys on your laptop can be stolen",
			[]string{
				"to fix: set AllowAgentForwarding no in /etc/ssh/sshd_config",
				"note: use ssh -A explicitly when you need forwarding, rather than leaving it on globally",
			},
		))
	}

	// ClientAliveInterval = 0 — no idle timeout; sessions left open indefinitely.
	// Unlike the sibling checks above (which fire on a bad *present* value), this one
	// fires on an *absent* setting, so the zero value also occurs when no sshd was
	// audited at all — gate on SSHAuditSource so a host with no sshd doesn't get told
	// to set ClientAliveInterval in a config it doesn't have. (TRIAGE §A minor.)
	if sec.SSHClientAliveInterval == 0 && sec.SSHAuditSource != "" && !sec.IsOffensiveDistro {
		out = append(out, insight("INFO", "Hardening",
			"SSH idle timeout not set — sessions stay open indefinitely (set ClientAliveInterval)",
			[]string{
				"to fix: set ClientAliveInterval 300 in /etc/ssh/sshd_config",
				"to fix: set ClientAliveCountMax 3 in /etc/ssh/sshd_config",
				"note: this disconnects idle sessions after 300s × 3 = 15 minutes",
			},
		))
	}

	// AllowUsers / AllowGroups — informational: good hygiene if configured
	// No WARN — absence isn't a misconfiguration, just an opportunity to note best practice
	// (already surfaced via password auth and root login checks)

	// ── Weak SSH algorithms (sshd -T or file parse) ───────────────────────────
	// Check only when we have algorithm data (non-empty strings from sshd -T or config).
	out = append(out, checkSSHWeakCiphers(sec)...)
	out = append(out, checkSSHWeakMACs(sec)...)
	out = append(out, checkSSHWeakKEX(sec)...)

	return out
}

// checkFailedLoginAttempts flags a burst of failed SSH logins in the last hour
// (sec.FailedLogins, populated from the auth log/journal scan — distinct from
// the 24h checkAuth(AuthInfo) path, which has its own key-only-host nuance).
func checkFailedLoginAttempts(sec models.SecurityInfo) []models.Insight {
	var out []models.Insight

	if sec.FailedLogins >= 20 {
		msg := fmt.Sprintf("%d failed login attempts in the last hour", sec.FailedLogins)
		if len(sec.FailedLoginIPs) > 0 {
			msg += fmt.Sprintf(" — top sources: %s", strings.Join(sec.FailedLoginIPs[:min(3, len(sec.FailedLoginIPs))], ", "))
		}
		out = append(out, insight("CRIT", "Hardening", msg,
			[]string{"to inspect: journalctl _COMM=sshd | grep -E 'Failed|penalty' | tail -20", "to inspect: last -f /var/log/wtmp | head -20", "to fix: consider fail2ban or firewall rules"},
		))
	} else if sec.FailedLogins >= 5 {
		out = append(out, insight("WARN", "Hardening",
			fmt.Sprintf("%d failed login attempts in the last hour", sec.FailedLogins),
			[]string{"to inspect: journalctl _COMM=sshd | grep -E 'Failed|penalty' | tail -20"},
		))
	}

	return out
}

// checkNetworkExposure covers what's reachable from outside: unexpected
// listening ports, the Cockpit management UI, and a firewall that would lock
// out SSH — all "is this host reachable in ways it shouldn't be" conditions.
func checkNetworkExposure(sec models.SecurityInfo) []models.Insight { //nolint:funlen // flat list of independent network-exposure conditions; splitting would harm readability
	var out []models.Insight

	// Unexpected listening ports — split into known services (INFO) vs truly unexpected (WARN)
	// Known service processes are auto-detected and downgraded to INFO with context.
	knownServiceProcesses := map[string]string{
		// Kubernetes / k8s distributions
		"kubelite":        "k8s/microk8s",
		"kubelet":         "k8s",
		"kube-apiserver":  "k8s",
		"kube-scheduler":  "k8s",
		"kube-controller": "k8s",
		"cluster-agent":   "k8s/microk8s",
		"containerd":      "container-runtime",
		"dockerd":         "docker",
		// Observability
		"prometheus":    "prometheus",
		"node_exporter": "prometheus",
		"grafana":       "grafana",
		"alertmanager":  "prometheus",
		// Databases
		"mysqld":       "mysql",
		"postgres":     "postgresql",
		"mongod":       "mongodb",
		"redis-server": "redis",
		// Web/proxy
		"nginx":   "nginx",
		"apache2": "apache",
		"httpd":   "apache",
		"traefik": "traefik",
		"haproxy": "haproxy",
	}

	var unexpectedPorts []string
	var knownPorts []string
	var knownServices []string
	var pvePorts []string
	var portHints []string
	portHints = append(portHints, "to inspect: ss -tlnp")

	for _, p := range sec.ListeningPorts {
		if p.Expected {
			continue
		}
		portStr := fmt.Sprintf("%d/%s", p.Port, p.Protocol)
		// Proxmox VE service ports (web UI 8006, spiceproxy 3128, rpcbind 111)
		// are mandatory on PVE — surface as INFO, never WARN (see BUG-016).
		if sec.IsPVE && IsPVEServicePort(p.Port) {
			pvePorts = append(pvePorts, portStr)
			continue
		}
		// Check if process is a known service
		serviceName := ""
		for proc, svc := range knownServiceProcesses {
			if strings.Contains(strings.ToLower(p.Process), proc) {
				serviceName = svc
				break
			}
		}
		if serviceName != "" {
			knownPorts = append(knownPorts, portStr)
			if !containsStr(knownServices, serviceName) {
				knownServices = append(knownServices, serviceName)
			}
		} else {
			unexpectedPorts = append(unexpectedPorts, portStr)
			portHints = append(portHints, fmt.Sprintf("to inspect: ss -tlnp | grep :%d", p.Port))
		}
	}

	// PVE service ports — informational only (expected on Proxmox VE)
	if len(pvePorts) > 0 {
		out = append(out, insight("INFO", "Hardening",
			fmt.Sprintf("%d PVE service port(s) listening (expected): %s — Proxmox web UI, spiceproxy, and rpcbind",
				len(pvePorts), strings.Join(pvePorts, ", ")),
			nil,
		))
	}

	// Known services — downgrade to INFO
	if len(knownPorts) > 0 {
		out = append(out, insight("INFO", "Hardening",
			fmt.Sprintf("%d port(s) from known service(s) (%s) listening on all interfaces — consider binding to specific interfaces in production",
				len(knownPorts), strings.Join(knownServices, ", ")),
			[]string{
				"to inspect: ss -tlnp",
				"to restrict: bind service to specific interface/IP instead of 0.0.0.0",
			},
		))
	}
	// Truly unexpected ports — keep as WARN
	if len(unexpectedPorts) > 0 {
		out = append(out, insight("WARN", "Hardening",
			fmt.Sprintf("%d unexpected port(s) listening on all interfaces: %s",
				len(unexpectedPorts), strings.Join(unexpectedPorts, ", ")),
			portHints,
		))
	}

	// Cockpit (port 9090) — informational: management UI exposed
	for _, p := range sec.ListeningPorts {
		if p.Port == 9090 {
			out = append(out, insight("INFO", "Hardening",
				"Cockpit management UI listening on port 9090 — ensure it is not exposed to the internet",
				[]string{
					"to inspect: systemctl status cockpit",
					"to restrict: configure AllowUnencrypted=false in /etc/cockpit/cockpit.conf",
					"to restrict: limit access with firewall-cmd --add-rich-rule",
				},
			))
			break
		}
	}

	// Firewall
	if sec.FirewallActive && !sec.SSHAllowed {
		out = append(out, insight("CRIT", "Hardening",
			fmt.Sprintf("firewall (%s) active but SSH (port 22) not in allowed services — you may lose remote access after reconnect", sec.FirewallType),
			[]string{
				"to fix (firewalld): firewall-cmd --add-service=ssh --permanent && firewall-cmd --reload",
				"to fix (ufw): ufw allow ssh",
			},
		))
	}

	return out
}

// checkPrivilegeEscalationVectors covers accounts/config that could let a
// low-privilege user (or an attacker who gets a shell) become root: NOPASSWD
// sudo, unexpected SUID binaries, non-root UID-0 accounts, and cron entries
// that pipe to a shell.
func checkPrivilegeEscalationVectors(sec models.SecurityInfo) []models.Insight {
	var out []models.Insight

	// Sudo NOPASSWD
	if len(sec.SudoNopasswd) > 0 {
		// On offensive distros (Kali, Parrot), NOPASSWD groups like %kali-trusted
		// and service accounts like _gvm are intentional defaults — downgrade to INFO.
		if sec.IsOffensiveDistro {
			out = append(out, insight("INFO", "Hardening",
				fmt.Sprintf("NOPASSWD sudo for: %s — expected on offensive security distro", strings.Join(sec.SudoNopasswd, ", ")),
				nil,
			))
		} else {
			out = append(out, insight("WARN", "Hardening",
				fmt.Sprintf("NOPASSWD sudo for: %s", strings.Join(sec.SudoNopasswd, ", ")),
				[]string{"to inspect: sudo -l", "to inspect: cat /etc/sudoers"},
			))
		}
	}

	// Unexpected SUID binaries
	if len(sec.SUIDBinaries) > 0 {
		out = append(out, insight("WARN", "Hardening",
			fmt.Sprintf("%d unexpected SUID binary(ies): %s", len(sec.SUIDBinaries),
				strings.Join(sec.SUIDBinaries[:min(3, len(sec.SUIDBinaries))], ", ")),
			[]string{"to inspect: find / -perm -4000 -type f 2>/dev/null"},
		))
	}

	// Non-root users with UID 0 — always CRIT
	if len(sec.UID0Users) > 0 {
		out = append(out, insight("CRIT", "Hardening",
			fmt.Sprintf("non-root user(s) with UID 0: %s", strings.Join(sec.UID0Users, ", ")),
			[]string{"to inspect: awk -F: '$3==0' /etc/passwd", "to inspect: getent passwd | awk -F: '$3==0'", "to fix: remove or reassign UID for affected accounts"},
		))
	}

	// Suspect cron entries
	if len(sec.SuspectCrons) > 0 {
		out = append(out, insight("WARN", "Hardening",
			fmt.Sprintf("%d suspect cron entry(ies) — pipes to shell or writes to sensitive paths", len(sec.SuspectCrons)),
			[]string{"to inspect: cat /etc/cron.d/* /var/spool/cron/crontabs/*", "to inspect: review entries piping to bash or wget/curl"},
		))
	}

	return out
}

// checkSecuritySELinuxDenials surfaces AVC denials grouped with fix commands
// (setsebool/custom). Named distinctly from heuristics_system.go's
// checkSELinuxDenials(KernelSecurityInfo) — that one gates the SELinux row's
// own WARN/CRIT threshold; this one is the `dsd security`/Hardening view.
func checkSecuritySELinuxDenials(sec models.SecurityInfo) []models.Insight {
	var out []models.Insight

	// SELinux denials — skip sentinel value (-1 = data unavailable)
	if sec.SELinuxDenials >= 10 {
		msg := fmt.Sprintf("%d SELinux denials in the last hour (mode: %s)", sec.SELinuxDenials, sec.SELinuxMode)
		hints := []string{
			"to inspect: ausearch -m avc -ts recent",
			"to inspect: sealert -a /var/log/audit/audit.log",
		}
		// Surface grouped AVC findings with fix commands
		for _, g := range sec.SELinuxAVCGroups {
			if g.Count < 3 {
				continue // skip rare one-offs
			}
			summary := fmt.Sprintf("  %s → %s [%s] ×%d", g.Scontext, g.Tcontext, g.Tclass, g.Count)
			if g.BooleanFix != "" {
				summary += fmt.Sprintf("  fix: setsebool -P %s on", g.BooleanFix)
			} else if g.FixCmd != "" {
				summary += fmt.Sprintf("  fix: %s", truncateSELinux(g.FixCmd, 80))
			}
			hints = append(hints, summary)
		}
		out = append(out, insight("WARN", "Hardening", msg, hints))
	}

	// SELinux port-label scan (§6-add-2) — proactive: catches a listening
	// service with no SELinux port label before SELinux ever logs a denial for it.
	if len(sec.SELinuxUnlabeledPorts) > 0 {
		hints := make([]string, 0, len(sec.SELinuxUnlabeledPorts)+1)
		hints = append(hints, "to inspect: semanage port -l")
		for _, p := range sec.SELinuxUnlabeledPorts {
			proc := p.Process
			if proc == "" {
				proc = "unknown process"
			}
			hints = append(hints, fmt.Sprintf("to fix: semanage port -a -t <service>_port_t -p %s %d  # %s", p.Protocol, p.Port, proc))
		}
		out = append(out, insight("WARN", "Hardening",
			fmt.Sprintf("%d listening port(s) have no SELinux port label", len(sec.SELinuxUnlabeledPorts)),
			hints,
		))
	}

	// SELinux chcon-vs-semanage context detection (§6-add-3): a denial-
	// implicated path whose context was set via chcon (not semanage fcontext)
	// will silently revert on the next restorecon/full relabel.
	if len(sec.SELinuxContextIssues) > 0 {
		hints := make([]string, 0, len(sec.SELinuxContextIssues)+1)
		hints = append(hints, "to fix: semanage fcontext -a -t <type> '<path>(/.*)?'  then  restorecon -Rv <path>")
		for _, ci := range sec.SELinuxContextIssues {
			hints = append(hints, fmt.Sprintf("%s — actual: %s, expected: %s", ci.Path, ci.ActualContext, ci.ExpectedContext))
		}
		out = append(out, insight("WARN", "Hardening",
			fmt.Sprintf("%d denial-implicated path(s) have a temporary chcon context — will be lost on the next relabel", len(sec.SELinuxContextIssues)),
			hints,
		))
	}

	return out
}

// checkAppArmorDenials surfaces AppArmor denials grouped by profile/operation/
// path — the `dsd security` (SecurityInfo.AppArmorGroups) analogue of
// checkSecuritySELinuxDenials above. Distinct from heuristics_system.go's
// checkAppArmorActive(KernelSecurityInfo), which drives `dsd health`'s
// KernelSec row from a different collector/model pair and a 1h window; this
// one covers the Hardening-view-only, 24h-windowed denial data collected
// alongside SELinux for this command specifically.
func checkAppArmorDenials(sec models.SecurityInfo) []models.Insight {
	var out []models.Insight

	switch {
	case len(sec.AppArmorGroups) > 0:
		hints := []string{
			"to inspect: aa-logprof",
			"to inspect: journalctl -t kernel -g 'apparmor=\"DENIED\"' --since '24 hours ago'",
		}
		for i, g := range sec.AppArmorGroups {
			if i >= 5 {
				hints = append(hints, fmt.Sprintf("... and %d more group(s)", len(sec.AppArmorGroups)-5))
				break
			}
			hints = append(hints, fmt.Sprintf("  %s [%s] %s ×%d", g.Profile, g.Operation, g.Path, g.Count))
		}
		out = append(out, insight("WARN", "Hardening",
			fmt.Sprintf("%d AppArmor denial group(s) in the last 24h", len(sec.AppArmorGroups)),
			hints,
		))
	case sec.AppArmorDenials > 0:
		out = append(out, insight("WARN", "Hardening",
			fmt.Sprintf("%d AppArmor denial(s) in the last 24h", sec.AppArmorDenials),
			[]string{"to inspect: journalctl -t kernel -g 'apparmor=\"DENIED\"' --since '24 hours ago'"},
		))
	}

	return out
}

// checkPAMFailures surfaces PAM authentication failures from non-sshd
// services (su, sudo, login, cron, ...) — sshd's own failures are already
// covered by checkFailedLoginAttempts's FailedLogins threshold, so any
// presence here is a genuinely separate signal and WARNs unconditionally (no
// numeric floor: these are typically low-volume, high-signal events — e.g. a
// single repeated `sudo` failure for a service account is already
// noteworthy, unlike SSH's internet-facing brute-force noise floor).
func checkPAMFailures(sec models.SecurityInfo) []models.Insight {
	if len(sec.PAMModuleFailures) == 0 {
		return nil
	}
	hints := []string{"to inspect: grep pam_unix /var/log/auth.log /var/log/secure 2>/dev/null | tail -20"}
	total := 0
	for i, f := range sec.PAMModuleFailures {
		total += f.Count
		if i < 5 {
			hints = append(hints, fmt.Sprintf("  %s: %s ×%d", f.Service, f.User, f.Count))
		}
	}
	return []models.Insight{insight("WARN", "Hardening",
		fmt.Sprintf("%d PAM authentication failure(s) in the last 24h across %d service(s)", total, len(sec.PAMModuleFailures)),
		hints,
	)}
}

// checkRHELSecurityHardening covers RHEL-family compliance tooling: system-wide
// crypto policy, auditd rule presence, and AIDE file-integrity monitoring.
func checkRHELSecurityHardening(sec models.SecurityInfo) []models.Insight {
	var out []models.Insight

	// RHEL/Rocky: crypto-policies — LEGACY is a security risk
	if sec.CryptoPolicy == "LEGACY" {
		out = append(out, insight("WARN", "Hardening",
			"system-wide crypto policy is LEGACY — weak algorithms (MD5, SHA-1, DH<1024) are permitted",
			[]string{
				"to inspect: update-crypto-policies --show",
				"to fix: update-crypto-policies --set DEFAULT",
			},
		))
	}

	// RHEL/Rocky: auditd running but no rules — security theater
	if sec.AuditRules == 0 && sec.SELinuxMode != "" {
		out = append(out, insight("WARN", "Hardening",
			"auditd is running but has no active rules — system calls and file access are not being audited",
			[]string{
				"to inspect: auditctl -l",
				"to fix: augenrules --load or add rules to /etc/audit/rules.d/",
			},
		))
	}

	// RHEL/Rocky: AIDE installed but database never initialised
	if sec.AIDEInstalled && !sec.AIDEDBExists {
		out = append(out, insight("WARN", "Hardening",
			"AIDE is installed but database has never been initialised — file integrity monitoring is inactive",
			[]string{
				"to fix: aide --init && mv /var/lib/aide/aide.db.new /var/lib/aide/aide.db",
			},
		))
	}

	// RHEL/Rocky: AIDE database stale (> 7 days)
	if sec.AIDEInstalled && sec.AIDEDBExists && sec.AIDELastRunDays > 7 {
		out = append(out, insight("WARN", "Hardening",
			fmt.Sprintf("AIDE file integrity database is %d day(s) old — run a fresh check", sec.AIDELastRunDays),
			[]string{
				"to fix: aide --check",
				"to automate: add 'aide --check' to cron or systemd timer",
			},
		))
	}

	return out
}

// checkSUSESecurityHardening covers SUSE-family support tooling: supportconfig
// freshness and SUSEConnect subscription expiry.
func checkSUSESecurityHardening(sec models.SecurityInfo) []models.Insight {
	var out []models.Insight

	// SUSE supportconfig — stale or never run
	if sec.SupportconfigAvailable {
		switch {
		case sec.SupportconfigLastRunDays == -1:
			out = append(out, insight("INFO", "Hardening",
				"supportconfig available but never run — collect before opening SUSE support ticket",
				[]string{"to run: supportconfig", "archives saved to /var/log/scc_*.txz"},
			))
		case sec.SupportconfigLastRunDays > 30:
			out = append(out, insight("INFO", "Hardening",
				fmt.Sprintf("supportconfig last run %d day(s) ago — consider refreshing before a support call", sec.SupportconfigLastRunDays),
				[]string{"to run: supportconfig"},
			))
		}
	}

	// SUSEConnect subscription expiry
	if sec.SUSEConnectRegistered {
		switch {
		case sec.SUSEConnectExpiresDays == 0:
			out = append(out, insight("CRIT", "Hardening",
				"SUSEConnect subscription EXPIRED — security patches no longer available",
				[]string{"to fix: renew subscription at https://scc.suse.com"},
			))
		case sec.SUSEConnectExpiresDays > 0 && sec.SUSEConnectExpiresDays <= 14:
			out = append(out, insight("CRIT", "Hardening",
				fmt.Sprintf("SUSEConnect subscription expires in %d day(s) — renew immediately", sec.SUSEConnectExpiresDays),
				[]string{"to fix: renew subscription at https://scc.suse.com"},
			))
		case sec.SUSEConnectExpiresDays > 14 && sec.SUSEConnectExpiresDays <= 30:
			out = append(out, insight("WARN", "Hardening",
				fmt.Sprintf("SUSEConnect subscription expires in %d day(s)", sec.SUSEConnectExpiresDays),
				[]string{"to fix: renew subscription at https://scc.suse.com"},
			))
		}
	}

	return out
}

// checkMacOSHardening covers macOS-specific posture (FileVault/SIP/Gatekeeper).
// Gated on IsDarwin so these never fire on Linux, where the fields are always
// zero-value false.
func checkMacOSHardening(sec models.SecurityInfo) []models.Insight {
	var out []models.Insight

	if sec.IsDarwin {
		if !sec.FileVaultEnabled {
			out = append(out, insight("WARN", "Hardening",
				"FileVault disk encryption is off — data is readable if the disk is removed",
				[]string{
					"to fix: System Settings → Privacy & Security → FileVault → Turn On",
				},
			))
		}
		if !sec.SIPEnabled {
			out = append(out, insight("CRIT", "Hardening",
				"System Integrity Protection (SIP) is disabled — system files are unprotected",
				[]string{
					"to fix: boot to Recovery, open Terminal, run: csrutil enable",
					"note: SIP disabled is required for some development tools — verify intentional",
				},
			))
		}
		if !sec.GatekeeperEnabled {
			out = append(out, insight("WARN", "Hardening",
				"Gatekeeper is disabled — unsigned apps can run without quarantine",
				[]string{
					"to fix: System Settings → Privacy & Security → set to App Store and identified developers",
					"or: sudo spctl --master-enable",
				},
			))
		}
	}

	return out
}

// CheckSecurityDrift is the exported entry point for the `dsd security --drift`
// path. It is deliberately NOT part of ApplyThresholds / `dsd health`.
func CheckSecurityDrift(diff *baseline.SecurityDiff) []models.Insight {
	return checkSecurityDrift(diff)
}

// checkSecurityDrift turns a security baseline diff into insights. Used by the
// `dsd security --drift` path only — it is NOT wired into `dsd health`, which
// stays fast and baseline-free.
func checkSecurityDrift(diff *baseline.SecurityDiff) []models.Insight {
	var out []models.Insight
	if diff == nil || !diff.HasChanges() {
		return out
	}

	// New SUID binary = CRIT — privilege escalation vector, the most serious drift.
	if len(diff.NewSUIDs) > 0 {
		out = append(out, insight("CRIT", "Hardening",
			fmt.Sprintf("%d new SUID binary(ies) since last security baseline", len(diff.NewSUIDs)),
			[]string{
				"to investigate: ls -la <path> && file <path>",
				"to update baseline once verified intentional: dsd security --save-baseline",
			},
		))
	}

	// Changed SSH config = WARN
	if len(diff.ChangedSSHFiles) > 0 {
		out = append(out, insight("WARN", "Hardening",
			fmt.Sprintf("%d SSH config file(s) changed since last security baseline", len(diff.ChangedSSHFiles)),
			[]string{
				"to review: inspect changes to sshd_config and restart sshd if intentional",
				"to update baseline once verified intentional: dsd security --save-baseline",
			},
		))
	}

	// Added SSH config file = WARN — a new sshd_config.d/*.conf drop-in can
	// silently re-enable PermitRootLogin or password auth.
	if len(diff.AddedSSHFiles) > 0 {
		out = append(out, insight("WARN", "Hardening",
			fmt.Sprintf("%d new SSH config file(s) since last security baseline", len(diff.AddedSSHFiles)),
			[]string{
				"to review: inspect the new drop-in(s) for PermitRootLogin/PasswordAuthentication overrides",
				"to update baseline once verified intentional: dsd security --save-baseline",
			},
		))
	}

	// Removed SSH config file = WARN — a deleted hardening drop-in reverts its
	// directives to the daemon default.
	if len(diff.RemovedSSHFiles) > 0 {
		out = append(out, insight("WARN", "Hardening",
			fmt.Sprintf("%d SSH config file(s) removed since last security baseline", len(diff.RemovedSSHFiles)),
			[]string{
				"to review: confirm the removed drop-in's hardening is still applied elsewhere",
				"to update baseline once verified intentional: dsd security --save-baseline",
			},
		))
	}

	// New sudo NOPASSWD = WARN
	if len(diff.NewSudoEntries) > 0 {
		out = append(out, insight("WARN", "Hardening",
			fmt.Sprintf("%d new sudoers NOPASSWD entry(ies) since last security baseline", len(diff.NewSudoEntries)),
			[]string{
				"to review: visudo and confirm each NOPASSWD grant is intentional",
				"to update baseline once verified intentional: dsd security --save-baseline",
			},
		))
	}

	// New suspect cron = WARN
	if len(diff.NewCronEntries) > 0 {
		out = append(out, insight("WARN", "Hardening",
			fmt.Sprintf("%d new suspect cron entry(ies) since last security baseline", len(diff.NewCronEntries)),
			[]string{
				"to review: inspect cron entries writing to sensitive paths",
				"to update baseline once verified intentional: dsd security --save-baseline",
			},
		))
	}

	return out
}

func checkFirewall(f models.FirewallInfo) []models.Insight {
	if !f.Available {
		// The firewall state could not be read (query failed — typically a non-root
		// run — or no nft/iptables tooling). Don't let !Available pass as a silent
		// "no firewall problems"; surface it as INFO (doesn't raise the verdict).
		if f.PVEFirewallActive {
			return []models.Insight{insight("INFO", "Firewall",
				"PVE firewall active (pve-firewall) — host firewall managed by Proxmox; base ruleset not read",
				[]string{"to inspect: pve-firewall status"},
			)}
		}
		if f.StatusReason != "" {
			return []models.Insight{insight("INFO", "Firewall",
				"firewall state not verified — "+f.StatusReason,
				[]string{"to inspect: nft list ruleset", "to inspect: iptables -L -n   (run as root)"},
			)}
		}
		return nil
	}
	if !f.Active || f.TotalRules == 0 {
		// On Proxmox VE, pve-firewall manages the host firewall and loads its
		// rules dynamically — an empty base ruleset is expected (see BUG-017).
		if f.PVEFirewallActive {
			return []models.Insight{insight("INFO", "Firewall",
				"PVE firewall active (pve-firewall) — host firewall managed by Proxmox",
				[]string{"to inspect: pve-firewall status", "to inspect: cat /etc/pve/firewall/cluster.fw"},
			)}
		}
		// On a cloud guest the network firewall is the provider's Security Group /
		// NSG / VPC rules — a layer dsd cannot read from inside the instance. An
		// empty host ruleset is expected there if you rely on the cloud firewall, so
		// don't assert "host unprotected" (a false alarm that reads as cloud-naive):
		// surface it as INFO and point at the layer dsd can't see.
		if f.CloudGuest {
			label, term, where := cloudFirewallLabels(f.CloudProvider)
			return []models.Insight{insight("INFO", "Firewall",
				fmt.Sprintf("%s has no active host rules — on %s, network filtering is typically enforced by the %s, which dsd cannot see from inside the guest", f.Backend, label, term),
				[]string{
					"to verify: " + where,
					fmt.Sprintf("note: no host rules is expected if you rely on the %s; otherwise add ufw/nft/iptables rules", term),
				})}
		}
		return []models.Insight{insight("WARN", "Firewall",
			fmt.Sprintf("%s is installed but no rules are active — host is unprotected", f.Backend),
			[]string{
				"to inspect: iptables -L -n",
				"to inspect: nft list ruleset",
				"note: consider enabling ufw, firewalld, or writing iptables/nft rules",
			})}
	}
	// Services listening on all interfaces but dropped by the INPUT policy — the
	// "service up but unreachable" footgun (common on Photon's default-DROP iptables).
	// Only set when the ruleset was fully parseable, so this never mis-flags a
	// reachable service. The 0.0.0.0 bind signals the service intends to be reachable,
	// so the firewall block is a likely misconfiguration → WARN.
	if len(f.BlockedListeners) > 0 {
		return []models.Insight{insight("WARN", "Firewall",
			fmt.Sprintf("%d service(s) listen on all interfaces but the INPUT policy is DROP with no rule permitting them — unreachable from outside: port(s) %s",
				len(f.BlockedListeners), joinInts(f.BlockedListeners)),
			[]string{
				"these services bound 0.0.0.0 (intent to be reachable) but the firewall drops new inbound to them",
				"to allow a port: iptables -A INPUT -p tcp --dport <PORT> -j ACCEPT  (then persist the rule)",
				"to inspect: iptables -nvL INPUT ; ss -ltn",
				"note: ignore if the service is meant to be internal-only",
			})}
	}
	return nil
}

func checkAuth(a models.AuthInfo) []models.Insight {
	if !a.Available {
		return nil // sshd not installed — row hidden
	}
	// The auth source could not be read (typically a non-root run where the
	// journal and /var/log/auth.log are both inaccessible). Surface that honestly
	// as INFO instead of letting FailedLast24h==0 read as a clean "no failures" —
	// a check that silently reads OK when it never ran is a false sense of security.
	if !a.Checked {
		msg := a.StatusReason
		if msg == "" {
			msg = "SSH auth log could not be read — failed-login detection skipped"
		}
		return []models.Insight{insight("INFO", "Auth", msg,
			[]string{"run as root (sudo) to verify SSH authentication failures"})}
	}
	if a.FailedLast24h == 0 {
		return nil
	}
	// keyOnly is true when we authoritatively know password authentication is
	// disabled (sshd -T read). Failed *password* attempts cannot succeed against a
	// key-only host, so the flood is internet background noise, not a credible
	// brute-force threat — report it as INFO, not a cry-wolf WARN. Unknown policy
	// (SSHConfigChecked false) keeps the WARN: we fail toward warning.
	keyOnly := a.SSHConfigChecked && !a.PasswordAuthEnabled

	var out []models.Insight
	if a.FailedLast24h > 1000 {
		if keyOnly {
			out = append(out, insight("INFO", "Auth",
				fmt.Sprintf("%d failed SSH login attempts in 24h — all rejected: password authentication is disabled (key-only), so these cannot succeed", a.FailedLast24h),
				[]string{"no action needed; to silence the log noise: consider fail2ban or sshguard"}))
		} else {
			hints := []string{
				"to inspect: journalctl _COMM=sshd --since '24 hours ago' | grep 'Failed password'",
				"to inspect: lastb | head -20",
				"to harden: set PasswordAuthentication no (key-only) so these attempts cannot succeed",
				"to fix:     consider fail2ban or sshguard",
			}
			if len(a.TopSources) > 0 {
				hints = append(hints, fmt.Sprintf("top attacker: %s (%d attempts)",
					a.TopSources[0].Source, a.TopSources[0].Count))
			}
			out = append(out, insight("WARN", "Auth",
				fmt.Sprintf("%d failed SSH login attempts in 24h — brute force likely", a.FailedLast24h),
				hints))
		}
	} else if a.FailedLast24h > 100 {
		out = append(out, insight("INFO", "Auth",
			fmt.Sprintf("%d failed SSH login attempts in 24h", a.FailedLast24h),
			[]string{"to inspect: journalctl _COMM=sshd --since '24 hours ago' | grep Failed"}))
	}
	if a.RootAttempts > 0 {
		// Root password login is impossible when password auth is off entirely, or
		// when PermitRootLogin is anything other than "yes" (no / prohibit-password /
		// without-password). In that case the root attempts are futile — INFO, and
		// the "set PermitRootLogin no" advice would be stale, so drop it.
		rootPwImpossible := a.SSHConfigChecked && (!a.PasswordAuthEnabled || !a.RootPasswordLoginAllowed)
		if rootPwImpossible {
			out = append(out, insight("INFO", "Auth",
				fmt.Sprintf("%d root login attempt(s) — all rejected: root password login is disabled", a.RootAttempts),
				[]string{"to verify: sshd -T | grep -E 'permitrootlogin|passwordauthentication'"}))
		} else {
			out = append(out, insight("WARN", "Auth",
				fmt.Sprintf("%d root login attempt(s) — ensure PermitRootLogin no in sshd_config", a.RootAttempts),
				[]string{
					"to inspect: grep PermitRootLogin /etc/ssh/sshd_config",
					"to fix:     echo 'PermitRootLogin no' >> /etc/ssh/sshd_config && systemctl restart sshd",
				}))
		}
	}
	return out
}

func checkAuditd(a models.AuditInfo) []models.Insight {
	if !a.Available {
		return nil
	}
	var out []models.Insight
	if !a.Running {
		out = append(out, insight("WARN", "Auditd",
			"auditd is installed but not running — compliance logging inactive",
			[]string{
				"to fix: systemctl enable --now auditd",
				"note: required for CIS/STIG compliance",
			}))
	}
	if a.AuditLogSizeUnreadable {
		out = append(out, insight("INFO", "Auditd",
			"audit log size not verified — /var/log/audit/audit.log is unreadable (re-run as root)",
			[]string{"to inspect: sudo ls -lh /var/log/audit/"}))
	} else if a.AuditLogSizeGB > 10 {
		out = append(out, insight("WARN", "Auditd",
			fmt.Sprintf("audit log is %.1f GB — consider log rotation", a.AuditLogSizeGB),
			[]string{
				"to inspect: ls -lh /var/log/audit/",
				"to fix:     auditctl -e 0 && truncate -s 0 /var/log/audit/audit.log && auditctl -e 1",
			}))
	}
	return out
}

// IsPVEServicePort reports whether a port is a mandatory Proxmox VE service
// port: 8006 (web UI), 3128 (spiceproxy), or 111 (rpcbind/portmapper).
// Exported as the single source of truth — cmd/security.go consumes it so the
// {8006, 3128, 111} set is not duplicated across packages.
func IsPVEServicePort(port int) bool {
	switch port {
	case 8006, 3128, 111:
		return true
	}
	return false
}

// containsStr returns true if s is in the slice ss.
func containsStr(ss []string, s string) bool {
	for _, v := range ss {
		if v == s {
			return true
		}
	}
	return false
}

// cloudFirewallLabels maps a cloud provider id to a human label, the name of its
// network-firewall construct, and a one-line "where to verify it" hint. Used to
// frame an empty host ruleset on a cloud guest honestly (the protection lives in
// a layer dsd cannot read from inside the instance).
func cloudFirewallLabels(provider string) (label, term, where string) {
	switch provider {
	case "aws":
		return "AWS EC2", "Security Group", "check the instance's Security Group rules in the EC2 console or `aws ec2 describe-security-groups`"
	case "azure":
		return "Azure", "Network Security Group (NSG)", "check the NIC/subnet NSG in the Azure portal or `az network nsg rule list`"
	case "gcp":
		return "GCP", "VPC firewall rules", "check the VPC firewall in the GCP console or `gcloud compute firewall-rules list`"
	default:
		return "cloud", "cloud network firewall", "check your provider's network firewall / security group configuration"
	}
}

// joinInts renders a sorted int slice as "22, 80, 443".
func joinInts(xs []int) string {
	parts := make([]string, len(xs))
	for i, x := range xs {
		parts[i] = strconv.Itoa(x)
	}
	return strings.Join(parts, ", ")
}

// truncateSELinux truncates a string for inline hint display.
func truncateSELinux(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}
