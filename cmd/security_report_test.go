package cmd

import (
	"strings"
	"testing"

	"github.com/keyorixhq/dashdiag/internal/models"
	"github.com/keyorixhq/dashdiag/internal/output"
)

// Golden-output tests for security.go's printSecurityReport (0% covered) — a
// single flat renderer over plain data structs (analysis.SecurityConcernCount
// and securityChecksLimited already have full coverage as pure functions;
// this confirms the renderer wires them, plus its own section logic, into the
// printed output). No t.Parallel() (corrupts captureStdout's shared os.Stdout
// swap).

func TestPrintSecItem(t *testing.T) {
	good := captureStdout(t, func() { printSecItem("PermitRootLogin", true, "no (secure)", "yes (INSECURE)", output.ModePlain) })
	if !strings.Contains(good, "no (secure)") {
		t.Errorf("ok=true should show the good value, got:\n%s", good)
	}
	bad := captureStdout(t, func() { printSecItem("PermitRootLogin", false, "no (secure)", "yes (INSECURE)", output.ModePlain) })
	if !strings.Contains(bad, "yes (INSECURE)") || !strings.Contains(bad, "WARN") {
		t.Errorf("ok=false should render WARN with the bad value, got:\n%s", bad)
	}
}

func TestWellKnownPort(t *testing.T) {
	if got := wellKnownPort(22); got != "sshd" {
		t.Errorf("wellKnownPort(22) = %q, want sshd", got)
	}
	if got := wellKnownPort(65535); got != "" {
		t.Errorf("an unknown port should return empty, got %q", got)
	}
}

func TestPrintSecurityReportListeningPorts(t *testing.T) {
	// A PVE service port must never be flagged unexpected even if the collector
	// didn't mark it Expected (BUG-016).
	pve := captureStdout(t, func() {
		printSecurityReport(&models.SecurityInfo{IsPVE: true, ListeningPorts: []models.PortEntry{
			{Port: 8006, Protocol: "tcp", Expected: false},
		}}, nil, output.ModePlain, 0)
	})
	if strings.Contains(pve, "unexpected") {
		t.Errorf("a PVE service port must not be flagged unexpected, got:\n%s", pve)
	}

	unexpected := captureStdout(t, func() {
		printSecurityReport(&models.SecurityInfo{ListeningPorts: []models.PortEntry{
			{Port: 31337, Protocol: "tcp", Process: "nc", Expected: false},
		}}, nil, output.ModePlain, 0)
	})
	if !strings.Contains(unexpected, "unexpected") {
		t.Errorf("a genuinely unexpected port should be flagged, got:\n%s", unexpected)
	}

	// A well-known port's service name should override a generic process label.
	wellKnown := captureStdout(t, func() {
		printSecurityReport(&models.SecurityInfo{ListeningPorts: []models.PortEntry{
			{Port: 22, Protocol: "tcp", Process: "systemd", Expected: true},
		}}, nil, output.ModePlain, 0)
	})
	if !strings.Contains(wellKnown, "sshd") {
		t.Errorf("port 22 should resolve to sshd even with a generic process name, got:\n%s", wellKnown)
	}
}

// TestPrintSecurityReportListeningPorts_SanitizesProcess guards Finding:
// internal-collectors-29-04. p.Process comes from /proc/<pid>/comm, which
// any unprivileged local process can set to an arbitrary string via
// prctl(PR_SET_NAME) — a process binding a listening socket with a crafted
// comm must not be able to inject terminal control/escape bytes into the
// ports table.
func TestPrintSecurityReportListeningPorts_SanitizesProcess(t *testing.T) {
	out := captureStdout(t, func() {
		printSecurityReport(&models.SecurityInfo{ListeningPorts: []models.PortEntry{
			{Port: 31337, Protocol: "tcp", Process: "\x1b[2Jevil\x1b[0m", Expected: false},
		}}, nil, output.ModePlain, 0)
	})
	if strings.ContainsRune(out, 0x1b) {
		t.Errorf("listening-ports output contains a raw ESC byte, got:\n%q", out)
	}
	if !strings.Contains(out, "evil") {
		t.Errorf("printable text around the escape sequence must survive sanitization, got:\n%q", out)
	}
}

// TestPrintSecurityReportListeningPorts_StripsControlChars guards terminal
// escape injection: the process name comes from /proc/<pid>/comm, which is
// attacker-influenced (a process can name itself anything), and must not
// carry raw control bytes into the terminal.
func TestPrintSecurityReportListeningPorts_StripsControlChars(t *testing.T) {
	out := captureStdout(t, func() {
		printSecurityReport(&models.SecurityInfo{ListeningPorts: []models.PortEntry{
			{Port: 31337, Protocol: "tcp", Process: "evil\x1b]0;pwned\x07", Expected: false},
		}}, nil, output.ModePlain, 0)
	})
	if strings.Contains(out, "\x1b") {
		t.Errorf("printSecurityReport output still contains ESC byte:\n%s", out)
	}
	if !strings.Contains(out, "evil]0;pwned") {
		t.Errorf("printSecurityReport output missing sanitized process name:\n%s", out)
	}
}

func TestPrintSecurityReportSudoNopasswd(t *testing.T) {
	none := captureStdout(t, func() { printSecurityReport(&models.SecurityInfo{}, nil, output.ModePlain, 0) })
	if !strings.Contains(none, "Sudo NOPASSWD entries: none") {
		t.Errorf("no entries and root-readable should say none, got:\n%s", none)
	}

	unknown := captureStdout(t, func() { printSecurityReport(&models.SecurityInfo{NeedsRoot: true}, nil, output.ModePlain, 0) })
	if !strings.Contains(unknown, "unknown (needs root)") {
		t.Errorf("non-root must not claim none when it couldn't verify, got:\n%s", unknown)
	}

	present := captureStdout(t, func() {
		printSecurityReport(&models.SecurityInfo{SudoNopasswd: []string{"deploy ALL=(ALL) NOPASSWD: ALL"}}, nil, output.ModePlain, 0)
	})
	if !strings.Contains(present, "deploy ALL") {
		t.Errorf("a NOPASSWD entry should be listed, got:\n%s", present)
	}
}

func TestPrintSecurityReportFirewall(t *testing.T) {
	active := captureStdout(t, func() {
		printSecurityReport(&models.SecurityInfo{FirewallActive: true, FirewallType: "firewalld", SSHAllowed: true}, nil, output.ModePlain, 0)
	})
	if !strings.Contains(active, "firewalld active") {
		t.Errorf("an active firewall should name its type, got:\n%s", active)
	}

	sshBlocked := captureStdout(t, func() {
		printSecurityReport(&models.SecurityInfo{FirewallActive: true, FirewallType: "ufw", SSHAllowed: false}, nil, output.ModePlain, 0)
	})
	if !strings.Contains(sshBlocked, "CRIT") {
		t.Errorf("an active firewall blocking SSH should render CRIT, got:\n%s", sshBlocked)
	}

	unprotected := captureStdout(t, func() {
		printSecurityReport(&models.SecurityInfo{FirewallToolingPresent: true, FirewallType: "nftables"}, nil, output.ModePlain, 0)
	})
	if !strings.Contains(unprotected, "unprotected") {
		t.Errorf("tooling present but no active rules must say unprotected (not silently 'none detected'), got:\n%s", unprotected)
	}

	unreadable := captureStdout(t, func() {
		printSecurityReport(&models.SecurityInfo{FirewallUnreadable: true, FirewallType: "iptables"}, nil, output.ModePlain, 0)
	})
	if !strings.Contains(unreadable, "not verified") {
		t.Errorf("an unreadable ruleset must say not verified, not 'none detected', got:\n%s", unreadable)
	}

	// internal-collectors-29-03: nft binary absent, only an on-disk config file
	// found — must NOT claim "active" (config presence doesn't prove a loaded
	// ruleset), and must not say "none detected" either (there IS circumstantial
	// evidence). Distinct wording from FirewallUnreadable's "run as root", since
	// running as root wouldn't help — the tool itself is missing.
	configOnly := captureStdout(t, func() {
		printSecurityReport(&models.SecurityInfo{FirewallConfigOnlyUnverified: true, FirewallType: "nftables"}, nil, output.ModePlain, 0)
	})
	if strings.Contains(configOnly, "Firewall: nftables active") {
		t.Errorf("a config-file-only nftables state must not claim active, got:\n%s", configOnly)
	}
	if strings.Contains(configOnly, "none detected") {
		t.Errorf("a config-file-only nftables state must not say none detected, got:\n%s", configOnly)
	}
	if !strings.Contains(configOnly, "not verified") {
		t.Errorf("a config-file-only nftables state should say not verified, got:\n%s", configOnly)
	}

	none := captureStdout(t, func() { printSecurityReport(&models.SecurityInfo{}, nil, output.ModePlain, 0) })
	if !strings.Contains(none, "Firewall: none detected") {
		t.Errorf("genuinely no firewall should say none detected, got:\n%s", none)
	}
}

func TestPrintSecurityReportSELinux(t *testing.T) {
	denials := captureStdout(t, func() {
		printSecurityReport(&models.SecurityInfo{SELinuxMode: "enforcing", SELinuxDenials: 5}, nil, output.ModePlain, 0)
	})
	if !strings.Contains(denials, "5 denial(s)") {
		t.Errorf("SELinux denials should be counted, got:\n%s", denials)
	}

	// Non-root: AVC data genuinely unreadable — must not be conflated with "no denials".
	unreadable := captureStdout(t, func() {
		printSecurityReport(&models.SecurityInfo{SELinuxMode: "enforcing", SELinuxDenials: -1}, nil, output.ModePlain, 0)
	})
	if !strings.Contains(unreadable, "unavailable") {
		t.Errorf("SELinuxDenials=-1 must say AVC data unavailable, not claim clean, got:\n%s", unreadable)
	}

	autoRelabel := captureStdout(t, func() {
		printSecurityReport(&models.SecurityInfo{SELinuxMode: "enforcing", SELinuxAutoRelabel: true}, nil, output.ModePlain, 0)
	})
	if !strings.Contains(autoRelabel, "relabel queued") {
		t.Errorf("a pending autorelabel should be flagged, got:\n%s", autoRelabel)
	}

	boolFix := captureStdout(t, func() {
		printSecurityReport(&models.SecurityInfo{SELinuxMode: "enforcing", SELinuxBooleans: []models.SELinuxBoolean{
			{Name: "httpd_can_network_connect", SetCmd: "setsebool -P httpd_can_network_connect on"},
		}}, nil, output.ModePlain, 0)
	})
	if !strings.Contains(boolFix, "httpd_can_network_connect") || !strings.Contains(boolFix, "setsebool") {
		t.Errorf("a relevant off boolean should show its exact fix command, got:\n%s", boolFix)
	}
}

func TestPrintSecurityReportAppArmor(t *testing.T) {
	enforcing := captureStdout(t, func() {
		printSecurityReport(&models.SecurityInfo{AppArmorMode: "enforce", AppArmorProfiles: 10}, nil, output.ModePlain, 0)
	})
	if !strings.Contains(enforcing, "All profiles enforcing") {
		t.Errorf("no complain-mode profiles should say all enforcing, got:\n%s", enforcing)
	}

	complain := captureStdout(t, func() {
		printSecurityReport(&models.SecurityInfo{AppArmorMode: "enforce", AppArmorProfiles: 10, AppArmorComplain: 2}, nil, output.ModePlain, 0)
	})
	if !strings.Contains(complain, "2 profile(s) in complain mode") {
		t.Errorf("complain-mode profiles should be counted, got:\n%s", complain)
	}
}

func TestPrintSecurityReportPAMAndSUID(t *testing.T) {
	pam := captureStdout(t, func() {
		printSecurityReport(&models.SecurityInfo{PAMLockedAccounts: []string{"bob"}}, nil, output.ModePlain, 0)
	})
	if !strings.Contains(pam, "bob") || !strings.Contains(pam, "faillock --reset") {
		t.Errorf("a locked account should be named with the unlock command, got:\n%s", pam)
	}

	moduleFailures := captureStdout(t, func() {
		printSecurityReport(&models.SecurityInfo{
			PAMModuleFailures: []models.PAMFailure{{Service: "sudo", User: "bob", Count: 3}},
		}, nil, output.ModePlain, 0)
	})
	if !strings.Contains(moduleFailures, "sudo") || !strings.Contains(moduleFailures, "bob") || !strings.Contains(moduleFailures, "×3") {
		t.Errorf("a PAM module failure should name the service/user/count, got:\n%s", moduleFailures)
	}

	both := captureStdout(t, func() {
		printSecurityReport(&models.SecurityInfo{
			PAMLockedAccounts: []string{"bob"},
			PAMModuleFailures: []models.PAMFailure{{Service: "su", User: "eve", Count: 1}},
		}, nil, output.ModePlain, 0)
	})
	if strings.Count(both, "\nPAM\n") != 1 {
		t.Errorf("locked accounts and module failures should render under one PAM header, got:\n%s", both)
	}
	if !strings.Contains(both, "bob") || !strings.Contains(both, "eve") {
		t.Errorf("both PAM sub-sections should render together, got:\n%s", both)
	}

	suid := captureStdout(t, func() {
		printSecurityReport(&models.SecurityInfo{SUIDBinaries: []string{"/tmp/evil"}}, nil, output.ModePlain, 0)
	})
	if !strings.Contains(suid, "/tmp/evil") {
		t.Errorf("an unexpected SUID binary should be named, got:\n%s", suid)
	}
}

// TestPrintSecurityReportMACAbsentFallback guards the explicit "MAC not
// active" line: it must appear when NEITHER SELinux nor AppArmor is active,
// and must NOT appear when either one is — the fallback exists to replace a
// silent two-section omission with an explicit not-applicable state, not to
// fire whenever one of the two happens to be inactive.
func TestPrintSecurityReportMACAbsentFallback(t *testing.T) {
	neither := captureStdout(t, func() {
		printSecurityReport(&models.SecurityInfo{}, nil, output.ModePlain, 0)
	})
	if !strings.Contains(neither, "No mandatory access control") {
		t.Errorf("neither SELinux nor AppArmor active should show the MAC-absent fallback, got:\n%s", neither)
	}

	selinuxOnly := captureStdout(t, func() {
		printSecurityReport(&models.SecurityInfo{SELinuxMode: "enforcing"}, nil, output.ModePlain, 0)
	})
	if strings.Contains(selinuxOnly, "No mandatory access control") {
		t.Errorf("SELinux active should suppress the MAC-absent fallback, got:\n%s", selinuxOnly)
	}

	apparmorOnly := captureStdout(t, func() {
		printSecurityReport(&models.SecurityInfo{AppArmorMode: "enforce", AppArmorProfiles: 5}, nil, output.ModePlain, 0)
	})
	if strings.Contains(apparmorOnly, "No mandatory access control") {
		t.Errorf("AppArmor active should suppress the MAC-absent fallback, got:\n%s", apparmorOnly)
	}
}

// TestPrintSecurityReportVerdict pins the three-way summary: concerns found,
// checks-limited (non-root, INFO — must not read healthy), and genuinely
// healthy. This is the false-OK boundary BUG-072 exists to guard.
func TestPrintSecurityReportVerdict(t *testing.T) {
	// Two zero-value collisions with real WARN conditions: AuditRules' zero
	// value matches a real "auditd running, 0 rules" WARN (the actual "not
	// tracked" sentinel is -1), and SSHStrictModes zero-values to false even
	// though real sshd defaults it to yes (secure). A genuinely clean baseline
	// must set both explicitly.
	clean := models.SecurityInfo{AuditRules: -1, SSHStrictModes: true}

	healthy := captureStdout(t, func() { printSecurityReport(&clean, nil, output.ModePlain, 0) })
	if !strings.Contains(healthy, "Security posture healthy") {
		t.Errorf("no concerns, fully verified should read healthy, got:\n%s", healthy)
	}

	limitedInfo := clean
	limitedInfo.NeedsRoot = true
	limited := captureStdout(t, func() { printSecurityReport(&limitedInfo, nil, output.ModePlain, 0) })
	if strings.Contains(limited, "Security posture healthy") {
		t.Errorf("checks-limited (non-root) must not claim healthy, got:\n%s", limited)
	}
	if !strings.Contains(limited, "checks limited") {
		t.Errorf("checks-limited should say so explicitly, got:\n%s", limited)
	}

	concern := captureStdout(t, func() {
		printSecurityReport(&models.SecurityInfo{SSHPermitRoot: true}, nil, output.ModePlain, 0)
	})
	if !strings.Contains(concern, "security concern(s) found") {
		t.Errorf("PermitRootLogin=yes should surface as a concern, got:\n%s", concern)
	}
}
