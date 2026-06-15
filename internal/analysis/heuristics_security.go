package analysis

import (
	"fmt"
	"strings"

	"github.com/keyorixhq/dashdiag/internal/baseline"
	"github.com/keyorixhq/dashdiag/internal/models"
)

func checkSecurity(sec models.SecurityInfo) []models.Insight { //nolint:funlen,cyclop // security checks are a flat list of independent conditions; splitting would harm readability
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

	// Failed logins
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

	// User account hardening (Spec 14)
	out = append(out, checkEmptyPasswords(sec)...)
	out = append(out, checkStalePasswords(sec)...)
	out = append(out, checkWorldWritable(sec)...)

	// macOS-specific checks — gated on IsDarwin so these never fire on Linux
	// (where FileVault/SIP/Gatekeeper fields are always zero-value false).
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
