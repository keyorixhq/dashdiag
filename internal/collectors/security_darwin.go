//go:build darwin

package collectors

import (
	"bufio"
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/keyorixhq/dashdiag/internal/models"
	"github.com/keyorixhq/dashdiag/internal/platform"
)

// SecurityCollector gathers macOS security posture: SSH config, listening
// ports, sudoers, the Application Firewall, FileVault/SIP/Gatekeeper state,
// and suspicious LaunchDaemons/LaunchAgents.
type SecurityCollector struct {
	profile platform.Profile
}

func NewSecurityCollector() *SecurityCollector { return &SecurityCollector{} }

// NewSecurityCollectorWithProfile mirrors the Linux constructor; the profile is
// currently unused on darwin but kept for signature parity across build tags.
func NewSecurityCollectorWithProfile(p platform.Profile) *SecurityCollector {
	return &SecurityCollector{profile: p}
}

func (c *SecurityCollector) Name() string           { return "Hardening" }
func (c *SecurityCollector) Timeout() time.Duration { return 8 * time.Second }

// CollectSUSEConnect is a no-op on darwin (SUSE-only).
func CollectSUSEConnect(_ context.Context, _ *models.SecurityInfo) {}

// ScanSUIDBinaries is a no-op on darwin (Linux SUID scan only).
func ScanSUIDBinaries(_ *models.SecurityInfo) {}

func (c *SecurityCollector) Collect(ctx context.Context) (interface{}, error) {
	info := &models.SecurityInfo{}

	// macOS uses BSM auditd, which is unrelated to Linux auditd rules. Mark the
	// Linux audit-rules check unavailable (-1) so neither the renderer nor the
	// heuristic fires the "auditd running, no rules" false positive. The struct
	// zero value is 0, which the renderer reads as "running with no rules", so
	// this must be set explicitly.
	info.AuditRules = -1

	parseDarwinSSHConfig(info)
	parseDarwinListeningPorts(ctx, info)
	parseDarwinSudoers(info)
	parseDarwinFirewall(info)
	parseDarwinSystemSecurity(info)
	parseDarwinSuspectLaunchd(ctx, info)

	return info, nil
}

// parseDarwinSSHConfig reads /etc/ssh/sshd_config and its drop-ins. macOS ships
// sshd_config with everything commented out and `sshd -T` fails without
// hostkeys, so we set OpenSSH defaults first and parse files directly.
func parseDarwinSSHConfig(info *models.SecurityInfo) {
	// OpenSSH defaults — these reflect what OpenSSH uses when the key is absent.
	info.SSHStrictModes = true  // StrictModes yes (default)
	info.SSHPubkeyAuth = true   // PubkeyAuthentication yes (default)
	info.SSHIgnoreRhosts = true // IgnoreRhosts yes (default)
	info.SSHPasswordAuth = true // PasswordAuthentication yes (macOS default)

	paths := []string{"/etc/ssh/sshd_config"}
	if dropins, err := filepath.Glob("/etc/ssh/sshd_config.d/*.conf"); err == nil {
		paths = append(paths, dropins...)
	}
	for _, p := range paths {
		parseDarwinSSHFile(p, info)
	}
}

// parseDarwinSSHFile parses the SSH keys that drive checkSecurity() heuristics.
// It deliberately covers only those keys — not a full sshd_config parse.
func parseDarwinSSHFile(path string, info *models.SecurityInfo) {
	data, err := os.ReadFile(path) // #nosec G304 -- well-known config path
	if err != nil {
		return
	}
	scanner := bufio.NewScanner(strings.NewReader(string(data)))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if strings.HasPrefix(line, "#") || line == "" {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		key := strings.ToLower(fields[0])
		val := strings.ToLower(fields[1])
		switch key {
		case "permitrootlogin":
			info.SSHRootLogin = val == "yes"
			info.SSHPermitRoot = val != "no" && val != "prohibit-password" && val != "without-password"
		case "passwordauthentication":
			info.SSHPasswordAuth = val == "yes"
		case "strictmodes":
			info.SSHStrictModes = val != "no"
		case "permitemptypasswords":
			info.SSHPermitEmptyPwd = val == "yes"
		case "maxauthtries":
			if n, err := strconv.Atoi(val); err == nil {
				info.SSHMaxAuthTries = n
			}
		case "clientaliveinterval":
			if n, err := strconv.Atoi(val); err == nil {
				info.SSHClientAliveInterval = n
			}
		}
	}
}

// parseDarwinListeningPorts uses lsof (macOS has no /proc/net/tcp).
func parseDarwinListeningPorts(ctx context.Context, info *models.SecurityInfo) {
	// -iTCP -sTCP:LISTEN — only TCP listening sockets
	// -n no hostname resolution, -P no port-name resolution (numbers)
	out, err := runCmd(ctx, "lsof", "-iTCP", "-sTCP:LISTEN", "-n", "-P")
	if err != nil {
		return
	}
	seen := map[int]bool{}
	for _, line := range strings.Split(out, "\n") {
		fields := strings.Fields(line)
		if len(fields) < 9 {
			continue
		}
		// COMMAND PID USER FD TYPE DEVICE SIZE/OFF NODE NAME
		// NAME: *:5432 or 127.0.0.1:5432 or [::]:5432
		name := fields[8]
		colon := strings.LastIndex(name, ":")
		if colon < 0 {
			continue
		}
		port, err := strconv.Atoi(name[colon+1:])
		if err != nil || seen[port] {
			continue
		}
		seen[port] = true
		info.ListeningPorts = append(info.ListeningPorts, models.PortEntry{
			Port:     port,
			Protocol: "tcp",
			Process:  fields[0],
			Expected: isDarwinExpectedPort(port),
		})
	}
}

func isDarwinExpectedPort(port int) bool {
	switch port {
	case 22, 80, 443:
		return true
	}
	return false
}

// parseDarwinSudoers scans /etc/sudoers and the sudoers.d drop-in dirs for
// NOPASSWD entries.
func parseDarwinSudoers(info *models.SecurityInfo) {
	paths := []string{"/etc/sudoers", "/private/etc/sudoers"}
	for _, p := range []string{"/private/etc/sudoers.d", "/etc/sudoers.d"} {
		if entries, err := filepath.Glob(p + "/*"); err == nil {
			paths = append(paths, entries...)
		}
	}
	seen := map[string]bool{}
	for _, p := range paths {
		if seen[p] {
			continue
		}
		seen[p] = true
		parseDarwinSudoersFile(p, info)
	}
}

func parseDarwinSudoersFile(path string, info *models.SecurityInfo) {
	f, err := os.Open(filepath.Clean(path)) // #nosec G304
	if err != nil {
		return
	}
	defer f.Close() //nolint:errcheck
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if strings.HasPrefix(line, "#") || !strings.Contains(line, "NOPASSWD") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) > 0 && fields[0] != "ALL" {
			info.SudoNopasswd = append(info.SudoNopasswd, fields[0])
		}
	}
}

// parseDarwinFirewall reads the macOS Application Firewall global state.
func parseDarwinFirewall(info *models.SecurityInfo) {
	fw := "/usr/libexec/ApplicationFirewall/socketfilterfw"
	out, err := exec.Command(fw, "--getglobalstate").Output() // #nosec G204 -- fixed path, no user input
	if err != nil {
		return
	}
	lower := strings.ToLower(strings.TrimSpace(string(out)))
	// "Firewall is enabled. (State = 1)" / "Firewall is disabled. (State = 0)"
	if strings.Contains(lower, "enabled") {
		info.FirewallActive = true
		info.FirewallType = "macOS Application Firewall"
	}
	// The Application Firewall doesn't gate the SSH port directly — Remote Login
	// is controlled separately under System Settings > Sharing. Treat SSH as
	// allowed so the "firewall active but SSH blocked" CRIT never false-fires.
	info.SSHAllowed = true
}

// parseDarwinSystemSecurity checks FileVault, SIP, and Gatekeeper. It also sets
// IsDarwin, which gates the macOS-specific heuristics in checkSecurity().
func parseDarwinSystemSecurity(info *models.SecurityInfo) {
	info.IsDarwin = true

	// FileVault disk encryption
	if out, err := exec.Command("fdesetup", "status").Output(); err == nil { // #nosec G204
		info.FileVaultEnabled = strings.Contains(strings.ToLower(string(out)), "filevault is on")
	}

	// System Integrity Protection
	if out, err := exec.Command("csrutil", "status").Output(); err == nil { // #nosec G204
		info.SIPEnabled = strings.Contains(strings.ToLower(string(out)), "enabled")
	}

	// Gatekeeper
	if out, err := exec.Command("spctl", "--status").Output(); err == nil { // #nosec G204
		info.GatekeeperEnabled = strings.Contains(strings.ToLower(string(out)), "assessments enabled")
	}
}

// parseDarwinSuspectLaunchd scans LaunchDaemons/LaunchAgents for persistence
// indicators — the macOS analogue of parseSuspectCrons on Linux. Findings reuse
// the SuspectCrons field, which drives the same heuristic.
func parseDarwinSuspectLaunchd(ctx context.Context, info *models.SecurityInfo) {
	_ = ctx
	dirs := []string{
		"/Library/LaunchDaemons",
		"/Library/LaunchAgents",
	}
	suspectPatterns := []string{
		"/tmp/", "/var/tmp/", // executing from world-writable
		"curl ", "wget ", // downloading at runtime
		"| bash", "| sh", "|bash", // piping to shell
		"chmod +s", "chmod 4", // setting SUID
		"/dev/tcp", // raw TCP (reverse shell indicator)
	}
	for _, dir := range dirs {
		entries, err := os.ReadDir(dir)
		if err != nil {
			continue
		}
		for _, e := range entries {
			if e.IsDir() || !strings.HasSuffix(e.Name(), ".plist") {
				continue
			}
			path := filepath.Join(dir, e.Name())
			data, err := os.ReadFile(filepath.Clean(path)) // #nosec G304
			if err != nil {
				continue
			}
			content := string(data)
			for _, pat := range suspectPatterns {
				if strings.Contains(content, pat) {
					info.SuspectCrons = append(info.SuspectCrons, e.Name()+": "+pat)
					break
				}
			}
		}
	}
}
