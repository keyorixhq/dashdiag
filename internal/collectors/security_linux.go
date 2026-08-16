//go:build linux

package collectors

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/keyorixhq/dashdiag/internal/models"
	"github.com/keyorixhq/dashdiag/internal/platform"
)

const (
	secValYes          = "yes"
	secTypeFile        = "file"
	secTypePort        = "port"
	secFwIPTables      = "iptables"
	secSvcHTTPD        = "httpd"
	secFldStatus       = "status"
	secSvcSSH          = "ssh"
	secFwNFTables      = "nftables"
	secFwFirewallCmd   = "firewall-cmd"
	secFldExpiresAt    = "expires_at"
	secTypeContainer   = "container"
	secValALL          = "ALL"
	secPfxUser         = "user="
	secProtoTCP        = "tcp"
	secFldSubscription = "subscription_status"
	secFldIdentifier   = "identifier"
	secValAllowed      = "allowed"
	secValActive       = "active"
)

// SecurityCollector reads system security posture directly from kernel and
// config files. No external tools except SUID detection (find).
type SecurityCollector struct {
	profile platform.Profile
}

func NewSecurityCollector() *SecurityCollector { return &SecurityCollector{} }

// NewSecurityCollectorWithProfile builds a collector that uses the platform
// Profile for distro-aware checks (e.g. offensive-distro detection).
func NewSecurityCollectorWithProfile(p platform.Profile) *SecurityCollector {
	return &SecurityCollector{profile: p}
}

func (c *SecurityCollector) Name() string           { return "Hardening" }
func (c *SecurityCollector) Timeout() time.Duration { return 10 * time.Second }

func (c *SecurityCollector) Collect(ctx context.Context) (interface{}, error) {
	info := &models.SecurityInfo{}

	if os.Getuid() != 0 {
		info.NeedsRoot = true
	}

	parseSSHConfig(ctx, info)
	parseFailedLogins(ctx, info)
	parseListeningPorts(info)
	parseSudoers(info)
	parseSELinuxDenials(ctx, info)
	parseUID0Users(info)
	parseSuspectCrons(info)
	parseFirewall(ctx, info)
	parseRHELSecurity(ctx, info)
	parseSupportconfig(info)
	parseAppArmor(info)
	parseSUSEConnect(ctx, info)
	// User account hardening (Spec 14)
	parsePasswordAging(info)
	parseWorldWritable(info)
	// Spec 6: SELinux booleans, AppArmor groups, autorelabel, PAM lockout
	parseSELinuxExtras(ctx, info)

	// Detect offensive/pentest distros and suppress false-positive security WARNs.
	// Kali Linux ships with PermitRootLogin yes, password auth, and no firewall by design.
	if c.isOffensiveDistro() {
		info.IsOffensiveDistro = true
	}

	// Proxmox VE hosts mandate ports 8006/3128/111 and root SSH login —
	// flag the host so the analysis layer suppresses those false positives.
	info.IsPVE = IsPVEHost()

	return info, nil
}

// parseSSHConfig reads the effective SSH daemon configuration.
// Strategy (in order):
//  1. `sshd -T` — reads the fully merged effective config including all drop-ins.
//     Requires root on RHEL/Rocky (sshd_config is 600). Falls through if unavailable.
//  2. Direct file parse of /etc/ssh/sshd_config + Include drop-ins.
//
// Both paths feed the same parseSSHFileContent parser since sshd -T output
// uses the same "key value" format as sshd_config.
func parseSSHConfig(ctx context.Context, info *models.SecurityInfo) {
	// Default values matching OpenSSH compiled defaults.
	// "Safe" defaults (enabled features) are true; "dangerous" defaults that
	// must be explicitly disabled are also true so a commented-out directive in
	// sshd_config (which leaves the compiled default active) is never silently
	// treated as the secure/disabled state by the file-parse fallback path.
	info.SSHPubkeyAuth = true      // compiled default: yes
	info.SSHStrictModes = true     // compiled default: yes
	info.SSHIgnoreRhosts = true    // compiled default: yes
	info.SSHPasswordAuth = true    // compiled default: yes — must be explicitly disabled
	info.SSHTCPForwarding = true   // compiled default: yes — must be explicitly disabled
	info.SSHAgentForwarding = true // compiled default: yes — must be explicitly disabled

	// Try sshd -T first — gives the fully merged effective configuration.
	// On RHEL 10 this requires root; non-root exits 0 but prints "Permission denied".
	if out, err := runCmd(ctx, "sshd", "-T"); err == nil {
		outStr := out
		if !strings.Contains(outStr, "Permission denied") && len(strings.TrimSpace(outStr)) > 0 {
			parseSSHFileContent(outStr, info)
			info.SSHAuditSource = "sshd -T"
			return
		}
	}

	// Fall back to file parsing (works without root, may miss drop-ins on some distros)
	readAny := parseSSHFile("/etc/ssh/sshd_config", info)
	for _, pattern := range []string{
		"/etc/ssh/sshd_config.d/*.conf",
		"/etc/ssh/sshd_config.d/*.cfg",
	} {
		if files, err := glob(pattern); err == nil {
			for _, f := range files {
				if parseSSHFile(f, info) {
					readAny = true
				}
			}
		}
	}
	if readAny {
		info.SSHAuditSource = secTypeFile
	} else {
		// Neither sshd -T nor any config file was readable. This means there is no
		// SSH evidence at all (container, minimal install, or permission denied on
		// all paths). Mark unreadable so that analysis skips SSH checks rather than
		// treating the pre-set dangerous compiled defaults (true) as real verdicts.
		info.SSHConfigUnreadable = true
	}
}

// parseSSHFile reads a single sshd_config file or drop-in and populates
// SecurityInfo. Returns true when the file was actually read. A permission-denied
// open on an existing file flags SSHConfigUnreadable so the analysis layer can
// say "couldn't audit SSH" instead of silently reporting the secure defaults as
// real (false-OK); a not-found file just means no SSH config there.
func parseSSHFile(path string, info *models.SecurityInfo) bool {
	f, err := openFile(path) // #nosec G304 -- only reads well-known config paths
	if err != nil {
		// A permission-denied or too-large read is "present but couldn't be
		// audited" — must not fall through to the caller treating this as
		// silently absent (which would report the compiled-in secure defaults
		// as real verdicts).
		if os.IsPermission(err) || errors.Is(err, errFileTooLarge) {
			info.SSHConfigUnreadable = true
		}
		return false
	}
	defer f.Close() //nolint:errcheck

	// Total-size cap on the accumulation loop itself (read-bounding-10),
	// defence-in-depth alongside openFile's own maxCappedFileBytes cap on the
	// reader it hands back — a config this large is never legitimate.
	content := new(strings.Builder)
	buf := make([]byte, 64*1024)
	total := 0
	for {
		n, readErr := f.Read(buf)
		if n > 0 {
			remaining := maxCappedFileBytes - total
			if remaining > 0 {
				take := n
				if take > remaining {
					take = remaining
				}
				content.Write(buf[:take])
				total += take
			}
		}
		if readErr != nil {
			break
		}
	}
	parseSSHFileContent(content.String(), info)
	return true
}

// parseSSHFileContent parses sshd_config content from a string — used by tests.
func parseSSHFileContent(content string, info *models.SecurityInfo) { //nolint:cyclop // NOSONAR — sshd_config has many independent directives; a flat scan reads clearest
	scanner := bufio.NewScanner(strings.NewReader(content))
	// inMatch tracks whether we're inside a conditional `Match` block. Directives
	// there are per-connection overrides, NOT the global policy we audit — e.g.
	// `PasswordAuthentication no` globally with `yes` inside `Match Address ...`
	// is a hardened config, and reading the Match value as global produced a false
	// "SSH allows password authentication" WARN on the file-parse fallback path.
	// Global directives precede the first Match; `Match all` returns to global.
	inMatch := false
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
		if key == "match" {
			inMatch = !strings.EqualFold(fields[1], "all")
			continue
		}
		if inMatch {
			continue // conditional override — not the global policy
		}
		val := strings.ToLower(fields[1])

		switch key {
		case "permitrootlogin":
			info.SSHRootLogin = val == secValYes
			// "without-password" is an alias for "prohibit-password" in older OpenSSH.
			// Both mean: key-based root login allowed, but not password-based.
			// This is a weaker restriction than "no" but not as bad as secValYes.
			info.SSHPermitRoot = val != "no" && val != "prohibit-password" && val != "without-password"
		case "passwordauthentication":
			info.SSHPasswordAuth = val == secValYes
		case "pubkeyauthentication":
			info.SSHPubkeyAuth = val == secValYes
		case secTypePort:
			if p, err := strconv.Atoi(val); err == nil && p != 22 {
				info.SSHPort = p
			}
		case "protocol":
			// Protocol 1 is deprecated and cryptographically broken
			if strings.Contains(val, "1") {
				info.SSHProtocol1 = true
			}
		case "maxauthtries":
			if n, err := strconv.Atoi(val); err == nil {
				info.SSHMaxAuthTries = n
			}
		case "logingracetime":
			// Value can be "30", "30s", "1m" etc.
			info.SSHLoginGraceTime = parseSSHDuration(val)
		case "allowusers":
			// AllowUsers can be a space-separated list on one line
			info.SSHAllowUsers = append(info.SSHAllowUsers, fields[1:]...)
		case "allowgroups":
			info.SSHAllowGroups = append(info.SSHAllowGroups, fields[1:]...)
		case "x11forwarding":
			info.SSHX11Forwarding = val == secValYes
		case "allowagentforwarding":
			info.SSHAgentForwarding = val == secValYes
		case "permitemptypasswords":
			info.SSHPermitEmptyPwd = val == secValYes
		case "strictmodes":
			// StrictModes defaults to yes — only flag when explicitly disabled
			info.SSHStrictModes = val != "no"
		case "clientaliveinterval":
			if n, err := strconv.Atoi(val); err == nil {
				info.SSHClientAliveInterval = n
			}
		case "clientalivecountmax":
			if n, err := strconv.Atoi(val); err == nil {
				info.SSHClientAliveCountMax = n
			}
		case "ignorerhosts":
			info.SSHIgnoreRhosts = val != "no"
		case "hostbasedauthentication":
			info.SSHHostbasedAuth = val == secValYes
		case "permituserenvironment":
			info.SSHPermitUserEnv = val == secValYes
		case "allowtcpforwarding":
			info.SSHTCPForwarding = val == secValYes
		case "loglevel":
			info.SSHLogLevel = strings.ToUpper(val)
		case "banner":
			info.SSHBanner = fields[1] // preserve original case for path
		case "maxsessions":
			if n, err := strconv.Atoi(val); err == nil {
				info.SSHMaxSessions = n
			}
		case "maxstartups":
			info.SSHMaxStartups = fields[1]
		case "ciphers":
			info.SSHCiphers = fields[1]
		case "macs":
			info.SSHMACs = fields[1]
		case "kexalgorithms":
			info.SSHKexAlgorithms = fields[1]
		}
	}
}

// parseSSHDuration converts sshd_config time formats to seconds.
// Handles: "30", "30s", "1m", "1m30s", "0" (disabled)
func parseSSHDuration(s string) int {
	s = strings.ToLower(strings.TrimSpace(s))
	if s == "0" || s == "none" {
		return 0
	}
	total := 0
	num := ""
	// clampMul/clampAdd saturate instead of overflowing negative — a garbled huge
	// duration must read as "very large" (over any limit), never wrap negative
	// (which would read as "well under the limit").
	add := func(mult int) {
		if n, err := strconv.Atoi(num); err == nil {
			total = clampAdd(total, clampMul(n, mult))
		}
		num = ""
	}
	for _, c := range s {
		switch {
		case c >= '0' && c <= '9':
			num += string(c)
		case c == 's':
			add(1)
		case c == 'm':
			add(60)
		case c == 'h':
			add(3600)
		case c == 'd':
			add(86400)
		case c == 'w':
			add(604800)
		}
	}
	// bare number without unit = seconds
	if num != "" {
		add(1)
	}
	return total
}

// parseFailedLogins counts failed SSH login attempts and their source IPs
// over the last hour, from journald (preferred) or /var/log/secure (RHEL) /
// /var/log/auth.log (Debian). Handles two sshd log formats:
//   - Legacy (OpenSSH ≤8): "Failed password for [invalid user] X from IP port P ssh2"
//   - Modern (OpenSSH 9+): "drop connection #N from [IP]:P on [IP]:P penalty: failed authentication"
func parseFailedLogins(ctx context.Context, info *models.SecurityInfo) {
	lines, unreadable := authLogSourceLines(ctx, "_COMM=sshd", "--since=1 hour ago", svcNoPager, "-q")
	if unreadable {
		info.FailedLoginsUnreadable = true
		return
	}

	cutoff := time.Now().Add(-1 * time.Hour)
	ipCount := make(map[string]int)
	for _, line := range lines {
		if len(line) < 15 {
			continue
		}
		if ts, err := parseLogTimestamp(line); err != nil || ts.Before(cutoff) {
			continue
		}

		var ip string
		switch {
		// Legacy format: "Failed password" or "Invalid user"
		case strings.Contains(line, "Failed password") || strings.Contains(line, "Invalid user"):
			if idx := strings.Index(line, " from "); idx >= 0 {
				rest := line[idx+6:]
				if ipEnd := strings.IndexByte(rest, ' '); ipEnd > 0 {
					ip = rest[:ipEnd]
				}
			}

		// Modern format (OpenSSH 9+): "drop connection #N from [IP]:port ... penalty: failed authentication"
		case strings.Contains(line, "penalty: failed authentication"):
			if idx := strings.Index(line, " from ["); idx >= 0 {
				rest := line[idx+7:]
				if ipEnd := strings.IndexByte(rest, ']'); ipEnd > 0 {
					ip = rest[:ipEnd]
				}
			}

		default:
			continue
		}

		info.FailedLogins++
		if net.ParseIP(ip) != nil {
			ipCount[ip]++
		}
	}

	// Top offending IPs
	for ip, count := range ipCount {
		if count >= 3 {
			info.FailedLoginIPs = append(info.FailedLoginIPs,
				fmt.Sprintf("%s (%d attempts)", ip, count))
		}
	}
}

// authLogSourceLines returns the auth-log lines to scan for failed-login/PAM
// analysis, preferring live journald over reading a flat file directly.
// journald is the current source of record on any systemd host; a flat file
// like /var/log/auth.log is just an optional rsyslog forwarding target that
// can silently stop being written (rsyslog imjournal cursor drift, forwarding
// disabled) while continuing to exist and pass a fileExists check — a
// file-first read has no way to tell "stale" from "current" and would report
// false negatives forever. unreadable is true only when NEITHER source could
// be read at all (no journalctl access and the file needs root, or auth
// logging isn't configured) — distinct from "read fine, found nothing".
func authLogSourceLines(ctx context.Context, journalArgs ...string) (lines []string, unreadable bool) {
	jCtx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	if out, err := runCmd(jCtx, "journalctl", journalArgs...); err == nil {
		return strings.Split(out, "\n"), false
	}

	paths := []string{"/var/log/secure", "/var/log/auth.log"}
	var logPath string
	for _, p := range paths {
		if fileExists(p) {
			logPath = p
			break
		}
	}
	if logPath == "" {
		return nil, true
	}

	f, err := openFile(logPath) // #nosec G304 -- hardcoded known paths
	if err != nil {
		return nil, true // exists but requires root
	}
	defer f.Close() //nolint:errcheck

	var out []string
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		out = append(out, scanner.Text())
	}
	// Line-count cap (internal-collectors-29-02) matching the varLogTailLines
	// convention logs_linux.go's syslog/messages fallback already uses — the
	// journalctl branch above is bounded by the global stream cap, but this
	// flat-file fallback had no per-line limit. Tail-preserving: the most
	// recent lines are what a failed-login/PAM scan cares about.
	if len(out) > varLogTailLines {
		out = out[len(out)-varLogTailLines:]
	}
	if err := scanner.Err(); err != nil {
		return out, false
	}
	return out, false
}

// parseLogTimestamp parses the leading timestamp of a syslog-style log line,
// in either format seen in the wild: classic BSD syslog ("Jan  2 15:04:05",
// no year — assumes current year) or rsyslog's ISO8601 RSYSLOG_FileFormat
// ("2026-07-07T20:00:34.410978+00:00"), which is Ubuntu/Debian's rsyslog
// default since ~20.04. A mismatch here silently fails every line (the
// caller treats a parse error as "too old"), which reads identically to an
// empty log — that's exactly how a live, correctly-forwarded auth.log went
// unnoticed as unparseable.
func parseLogTimestamp(line string) (time.Time, error) {
	if sp := strings.IndexByte(line, ' '); sp > 0 && strings.Contains(line[:sp], "-") {
		return time.Parse(time.RFC3339Nano, line[:sp])
	}
	if len(line) < 15 {
		return time.Time{}, fmt.Errorf("log line too short for a timestamp: %q", line)
	}
	year := time.Now().Year()
	return time.Parse("2006 Jan  2 15:04:05", fmt.Sprintf("%d %s", year, line[:15]))
}

// parseListeningPorts reads /proc/net/tcp and /proc/net/tcp6 directly.
// Only reports ports listening on 0.0.0.0 (all interfaces).
func parseListeningPorts(info *models.SecurityInfo) {
	for _, path := range []string{"/proc/net/tcp", "/proc/net/tcp6"} {
		parseProcNetTCP(path, info)
	}
}

func parseProcNetTCP(path string, info *models.SecurityInfo) {
	f, err := openFile(path) // #nosec G304 -- hardcoded /proc path
	if err != nil {
		return
	}
	defer f.Close() //nolint:errcheck

	// Build inode→process map — only works as root
	inodeProc, hasRoot := buildInodeProcMap()

	scanner := bufio.NewScanner(f)
	scanner.Scan() // skip header
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) < 10 {
			continue
		}
		if fields[3] != "0A" {
			continue
		}
		localAddr := fields[1]
		parts := strings.SplitN(localAddr, ":", 2)
		if len(parts) != 2 {
			continue
		}
		addrHex := parts[0]
		if addrHex != "00000000" && addrHex != "00000000000000000000000000000000" {
			continue
		}
		portHex := parts[1]
		port64, err := strconv.ParseInt(portHex, 16, 32)
		if err != nil {
			continue
		}
		port := int(port64)
		inode := fields[9]
		proc := inodeProc[inode]
		procName := proc.Name

		seen := false
		for _, p := range info.ListeningPorts {
			if p.Port == port {
				seen = true
				break
			}
		}
		if !seen {
			// Resolve systemd socket-activated services to their real name
			if procName == "systemd" || procName == "" {
				if name := wellKnownPortName(port); name != "" {
					procName = name
				}
			}
			info.ListeningPorts = append(info.ListeningPorts, models.PortEntry{
				Port:     port,
				Protocol: secProtoTCP,
				Process:  procName,
				ExePath:  proc.ExePath,
				Expected: isExpectedPort(port),
			})
		}
	}
	if err := scanner.Err(); err != nil {
		_ = err // best-effort; port list may be incomplete
	}
	if !hasRoot || os.Getuid() != 0 {
		info.PortsNeedRoot = true
	}
}

// inodeProcInfo pairs a process's self-reported name (/proc/<pid>/comm) with
// its exe symlink target (/proc/<pid>/exe) — the latter names the actual
// binary the kernel executed and, unlike comm, cannot be spoofed by the
// process itself via prctl(PR_SET_NAME) or argv[0]. A "known service"
// classification must corroborate against ExePath, not comm alone.
type inodeProcInfo struct {
	Name    string
	ExePath string
}

// buildInodeProcMap builds a map of socket inode → process identity.
// Returns the map and a bool indicating whether root-level fd access was available.
func buildInodeProcMap() (map[string]inodeProcInfo, bool) {
	result := make(map[string]inodeProcInfo)
	dirs, err := glob("/proc/[0-9]*/fd")
	if err != nil {
		return result, false
	}
	hasRoot := false
	for _, fdDir := range dirs {
		parts := strings.Split(fdDir, "/")
		if len(parts) < 3 {
			continue
		}
		pid := parts[2]
		comm, err := readFile("/proc/" + pid + "/comm") // #nosec G304
		if err != nil {
			continue
		}
		proc := inodeProcInfo{Name: strings.TrimSpace(string(comm))}
		if exe, err := readLink("/proc/" + pid + "/exe"); err == nil {
			proc.ExePath = exe
		}
		fds, err := readDirEntries(fdDir)
		if err != nil {
			continue
		}
		hasRoot = true // we could read at least one process's fds
		for _, fd := range fds {
			link, err := readLink(fdDir + "/" + fd.Name())
			if err != nil {
				continue
			}
			if strings.HasPrefix(link, "socket:[") && strings.HasSuffix(link, "]") {
				inode := link[8 : len(link)-1]
				if _, exists := result[inode]; !exists {
					result[inode] = proc
				}
			}
		}
	}
	return result, hasRoot
}

// isExpectedPort returns true for universally standard ports that are
// almost never a security concern. Kubernetes and other services are
// intentionally NOT listed here — users should see them and decide.
// Backlog: let users configure expected ports via dsd config.
func isExpectedPort(port int) bool {
	expected := map[int]bool{
		22:    true, // SSH
		80:    true, // HTTP
		443:   true, // HTTPS
		9090:  true, // Cockpit (RHEL web console)
		5355:  true, // LLMNR (systemd-resolved, Fedora/Ubuntu)
		10250: true, // kubelet (k8s/k3s node)
		10255: true, // kubelet read-only
		6443:  true, // kube-apiserver
		2379:  true, // etcd
		2380:  true, // etcd peer
	}
	return expected[port]
}

// sudoersPath is the primary sudoers file, referenced by parseSudoers and parseSudoersFile.
var sudoersPath = "/etc/sudoers"

// parseSudoers scans /etc/sudoers and /etc/sudoers.d/ for NOPASSWD entries.
func parseSudoers(info *models.SecurityInfo) {
	paths := []string{sudoersPath}
	if entries, err := glob("/etc/sudoers.d/*"); err == nil {
		paths = append(paths, entries...)
	}
	for _, p := range paths {
		parseSudoersFile(p, info)
	}
}

func parseSudoersFile(path string, info *models.SecurityInfo) {
	f, err := openFile(filepath.Clean(path))
	if err != nil {
		if path == sudoersPath {
			// Primary sudoers file exists but is unreadable — signal to CIS rules
			// that we can't distinguish "no NOPASSWD" from "couldn't check".
			if _, statErr := statFile(sudoersPath); statErr == nil {
				info.SudoersUnreadable = true
			}
		}
		return
	}
	defer f.Close() //nolint:errcheck

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if strings.HasPrefix(line, "#") {
			continue
		}
		// Defaults directives: scan for CIS 5.3.2 (use_pty), 5.3.3 (logfile), 5.3.5 (timestamp_timeout)
		if strings.HasPrefix(line, "Defaults") {
			if strings.Contains(line, "use_pty") {
				info.SudoDefaultsPTY = true
			}
			if strings.Contains(line, "logfile=") {
				info.SudoDefaultsLogfile = true
			}
			if idx := strings.Index(line, "timestamp_timeout="); idx >= 0 {
				valStr := line[idx+len("timestamp_timeout="):]
				end := 0
				for end < len(valStr) && (valStr[end] == '-' || (valStr[end] >= '0' && valStr[end] <= '9')) {
					end++
				}
				if end > 0 {
					if n, err := strconv.Atoi(valStr[:end]); err == nil {
						if n < 0 {
							info.SudoTimestampNever = true
						} else {
							info.SudoTimestampMins = n
						}
					}
				}
			}
		}
		if !strings.Contains(line, "NOPASSWD") {
			continue
		}
		// Extract the user/group — first field before whitespace
		fields := strings.Fields(line)
		if len(fields) > 0 {
			user := fields[0]
			// A system-wide (user secValALL) NOPASSWD rule for a SPECIFIC command is
			// benign and noisy (e.g. Mint's mintdrivers/mintupdate) — skip it. But
			// "ALL ... NOPASSWD: ALL" is full passwordless root for everyone, the
			// most dangerous escalation there is; it must NOT be skipped.
			if user == secValALL && !sudoGrantsAllCommands(line) {
				continue
			}
			info.SudoNopasswd = append(info.SudoNopasswd, user)
		}
	}
	if err := scanner.Err(); err != nil {
		_ = err // best-effort; sudoers list may be incomplete
	}
}

// sudoGrantsAllCommands reports whether a sudoers line grants NOPASSWD for ALL
// commands (e.g. "ALL ALL=(ALL:ALL) NOPASSWD: ALL" — full passwordless root) as
// opposed to a specific command (e.g. "ALL ALL=(root) NOPASSWD: /usr/sbin/mintdrivers").
func sudoGrantsAllCommands(line string) bool {
	idx := strings.LastIndex(line, "NOPASSWD:")
	if idx < 0 {
		return false
	}
	cmds := strings.TrimSpace(line[idx+len("NOPASSWD:"):])
	// First command in a possibly comma-separated list; secValALL means all commands.
	first := strings.TrimSpace(strings.SplitN(cmds, ",", 2)[0])
	return first == secValALL
}

// parseSELinuxDenials reads the audit log directly for recent AVC denials.
func parseSELinuxDenials(ctx context.Context, info *models.SecurityInfo) {
	// Check if SELinux is active
	mode, err := readFile("/sys/fs/selinux/enforce") // #nosec G304
	if err != nil {
		return // SELinux not present
	}
	switch strings.TrimSpace(string(mode)) {
	case "1":
		info.SELinuxMode = "enforcing"
	case "0":
		info.SELinuxMode = "permissive"
	default:
		return
	}

	// Try audit log (root) then ausearch fallback (non-root).
	n, ok := countAVCsFromAuditLog(1 * time.Hour)
	if ok {
		info.SELinuxDenials = n
	} else {
		// Neither audit.log nor ausearch available — flag as incomplete
		info.SELinuxDenials = -1 // sentinel: unknown
	}

	// Structured AVC grouping (root only — requires audit.log access)
	if getuid() == 0 && n > 0 {
		info.SELinuxAVCGroups = parseAVCGroups(ctx, 1*time.Hour)
	}

	_ = ctx // reserved for future timeout use
}

// SUIDBinScanPaths are filesystem roots to scan for unexpected SUID binaries.
// Deliberately excludes /proc and /sys virtual filesystems. Exported so tests
// can redirect the scan to a temp directory (the real paths can be enormous on
// CI runners with large tool caches).
var SUIDBinScanPaths = []string{"/usr/local", "/opt", "/home", "/tmp", "/var/tmp"}

// knownSUIDBinaries are expected SUID binaries — these are not flagged.
var knownSUIDBinaries = map[string]bool{
	"/usr/bin/sudo": true, "/usr/bin/su": true, "/usr/bin/passwd": true,
	"/usr/bin/newgrp": true, "/usr/bin/chsh": true, "/usr/bin/chfn": true,
	"/usr/bin/mount": true, "/usr/bin/umount": true, "/usr/bin/ping": true,
	"/usr/sbin/unix_chkpwd": true,
}

// ScanSUIDBinaries populates info.SUIDBinaries by scanning non-standard paths.
// Exported for the `dsd security --save-baseline`/`--drift` paths, which need
// the SUID list but must not pay this filesystem-walk cost on every `dsd health`
// run (Collect intentionally skips it).
func ScanSUIDBinaries(info *models.SecurityInfo) {
	findUnexpectedSUIDs(info)
}

// findUnexpectedSUIDs scans non-standard paths for SUID binaries.
// Called separately as it can be slow on large filesystems.
func findUnexpectedSUIDs(info *models.SecurityInfo) {
	for _, root := range SUIDBinScanPaths {
		walkSUIDDir(root, info)
	}
}

// walkSUIDDir recursively scans dir via the active source (readDirEntries +
// statFile), not raw filepath.Walk — which reads the live filesystem directly
// and so, under `dsd replay`, would scan the REPLAYING machine instead of the
// captured bundle. statFile's Mode is a portable os.FileMode, which Go's os
// package already maps from the raw stat mode bits — os.ModeSetuid is set
// exactly when the Unix setuid bit is, so no syscall.Stat_t is needed.
func walkSUIDDir(dir string, info *models.SecurityInfo) {
	entries, err := readDirEntries(dir)
	if err != nil {
		return
	}
	for _, e := range entries {
		path := filepath.Join(dir, e.Name())
		if e.IsDir() {
			walkSUIDDir(path, info)
			continue
		}
		fi, err := statFile(path)
		if err != nil {
			continue
		}
		if fi.Mode&os.ModeSetuid != 0 && !knownSUIDBinaries[path] {
			info.SUIDBinaries = append(info.SUIDBinaries, path)
		}
	}
}

// parseSELinuxExtras adds booleans, AppArmor groups, autorelabel, and PAM
// lockout + module-failure diagnosis.
func parseSELinuxExtras(ctx context.Context, info *models.SecurityInfo) {
	// /.autorelabel — full filesystem relabel queued
	if fileExists("/.autorelabel") {
		info.SELinuxAutoRelabel = true
	}

	// Relevant off booleans for denied scontexts
	if len(info.SELinuxAVCGroups) > 0 {
		info.SELinuxBooleans = collectRelevantBooleans(ctx, info.SELinuxAVCGroups)
	}

	// Deeper SELinux diagnosis (port labels, chcon-vs-semanage) — only once
	// there's already a signal something's wrong (§6-add-2, §6-add-3): mirrors
	// the primer's escalation order (booleans → AVC → port → context →
	// audit2allow) and avoids paying extra shell-outs on a quiet enforcing host.
	if selinuxDeepDiagnosisGate(info) {
		info.SELinuxUnlabeledPorts = parseSELinuxUnlabeledPorts(ctx, info.ListeningPorts)
		info.SELinuxContextIssues = parseSELinuxContextIssues(ctx, info.SELinuxAVCGroups)
	}

	// AppArmor denial grouping (Debian/Ubuntu/SUSE)
	if info.AppArmorMode != "" && info.AppArmorMode != "disabled" {
		var readable bool
		info.AppArmorGroups, readable = collectAppArmorDenials(ctx)
		info.AppArmorDenialsUnreadable = !readable
		info.AppArmorDenials = 0
		for _, g := range info.AppArmorGroups {
			info.AppArmorDenials += g.Count
		}
	}

	// PAM locked accounts via faillock
	info.PAMLockedAccounts = collectPAMLockedAccounts(ctx)

	// PAM module failures (su/sudo/login/cron) — §6 permission root-cause
	parsePAMModuleFailures(ctx, info)
}

// pamKey groups a PAM module failure by service+user.
type pamKey struct{ service, user string }

// parsePAMModuleFailures scans the same auth log source as parseFailedLogins
// for pam_unix authentication failures from services OTHER than sshd — su,
// sudo, login, cron, etc. sshd failures are already counted by FailedLogins
// (1h window); this is a distinct, non-network privilege/auth vector,
// counted over 24h.
func parsePAMModuleFailures(ctx context.Context, info *models.SecurityInfo) {
	lines, unreadable := authLogSourceLines(ctx, "--since=24 hours ago", svcNoPager, "-q",
		"-g", "pam_unix.*authentication failure")
	if unreadable {
		info.PAMFailuresUnreadable = true
		return
	}

	cutoff := time.Now().Add(-24 * time.Hour)
	counts := make(map[pamKey]int)
	for _, line := range lines {
		if len(line) < 15 {
			continue
		}
		if ts, err := parseLogTimestamp(line); err != nil || ts.Before(cutoff) {
			continue
		}
		if k, ok := parsePAMFailureLine(line); ok {
			counts[k]++
		}
	}
	info.PAMModuleFailures = pamFailuresFromCounts(counts)
}

// parsePAMFailureLine extracts (service, user) from a
// "pam_unix(SERVICE:auth): authentication failure ... user=USER" log line.
// sshd is deliberately excluded — FailedLogins already covers it via a
// different (1h, IP-focused) counter, and double-counting the same signal
// under two thresholds would confuse the verdict.
func parsePAMFailureLine(line string) (pamKey, bool) {
	if !strings.Contains(line, "pam_unix(") || !strings.Contains(line, "authentication failure") {
		return pamKey{}, false
	}
	// extractAAField stops at the first space/quote; pam_unix(service:auth)
	// has no space before ":auth)", so cut off everything after the colon.
	svc, _, _ := strings.Cut(extractAAField(line, "pam_unix("), ":")
	if svc == "" || svc == "sshd" {
		return pamKey{}, false
	}
	// A leading space distinguishes the secPfxUser field from "ruser=", which
	// contains secPfxUser as a substring — a bare extractAAField(line, secPfxUser)
	// would match inside "ruser=bob" and silently report the wrong account.
	user := extractAAField(line, " user=")
	if user == "" {
		return pamKey{}, false
	}
	return pamKey{service: svc, user: user}, true
}

// pamFailuresFromCounts converts a (service,user) tally into a sorted,
// deterministic []models.PAMFailure — map iteration order is non-deterministic
// and would otherwise produce spurious `dsd diff`/replay churn (same
// rationale as collectAppArmorDenials's own sort).
func pamFailuresFromCounts(counts map[pamKey]int) []models.PAMFailure {
	out := make([]models.PAMFailure, 0, len(counts))
	for k, c := range counts {
		out = append(out, models.PAMFailure{Service: k.service, User: k.user, Count: c})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Count != out[j].Count {
			return out[i].Count > out[j].Count
		}
		if out[i].Service != out[j].Service {
			return out[i].Service < out[j].Service
		}
		return out[i].User < out[j].User
	})
	return out
}

// selinuxDeepDiagnosisGate reports whether info justifies the additional
// SELinux port-label and file-context checks: SELinux must be enforcing or
// permissive AND at least one AVC denial must be present in the window.
func selinuxDeepDiagnosisGate(info *models.SecurityInfo) bool {
	return (info.SELinuxMode == "enforcing" || info.SELinuxMode == "permissive") && info.SELinuxDenials > 0
}

// ── Port-label scan (§6-add-2) ────────────────────────────────────────────────

// parseSELinuxUnlabeledPorts cross-references already-collected listening
// ports against `semanage port -l` and returns any with no matching SELinux
// port type — a proactive check that catches a labeling gap before SELinux
// ever logs a denial for it (the service just hasn't (re)bound under
// enforcement since the gap appeared).
func parseSELinuxUnlabeledPorts(ctx context.Context, listening []models.PortEntry) []models.SELinuxUnlabeledPort {
	out, err := runCmdTimeout(ctx, 5*time.Second, "semanage", secTypePort, "-l")
	if err != nil {
		return nil // semanage unavailable (not installed / no policy-utils) — unknown, not "unlabeled"
	}
	labeled := parseSemanagePortRanges(out)

	var unlabeled []models.SELinuxUnlabeledPort
	for _, p := range listening {
		if portRangeContains(labeled, p.Protocol, p.Port) {
			continue
		}
		unlabeled = append(unlabeled, models.SELinuxUnlabeledPort{
			Port: p.Port, Protocol: p.Protocol, Process: p.Process,
		})
	}
	return unlabeled
}

// semanagePortRange is one `semanage port -l` row: a proto + inclusive port
// range (a single port is lo==hi).
type semanagePortRange struct {
	proto  string
	lo, hi int
}

// parseSemanagePortRanges parses `semanage port -l` output, e.g.:
//
//	SELinux Port Type              Proto  Port Number
//
//	http_port_t                    tcp    80, 443, 8008-8010
//	ssh_port_t                     tcp    22
//
// Header/blank lines are skipped naturally — their 2nd field is never secProtoTCP/"udp".
func parseSemanagePortRanges(out string) []semanagePortRange {
	var ranges []semanagePortRange
	for _, line := range strings.Split(out, "\n") {
		fields := strings.Fields(line)
		if len(fields) < 3 {
			continue
		}
		proto := fields[1]
		if proto != secProtoTCP && proto != "udp" {
			continue
		}
		for _, tok := range strings.Split(strings.Join(fields[2:], ""), ",") {
			if lo, hi, ok := parsePortRangeToken(tok); ok {
				ranges = append(ranges, semanagePortRange{proto: proto, lo: lo, hi: hi})
			}
		}
	}
	return ranges
}

// parsePortRangeToken parses a single semanage port token: "22" or "8008-8010".
func parsePortRangeToken(tok string) (lo, hi int, ok bool) {
	tok = strings.TrimSpace(tok)
	if idx := strings.IndexByte(tok, '-'); idx > 0 {
		lo, errLo := strconv.Atoi(tok[:idx])
		hi, errHi := strconv.Atoi(tok[idx+1:])
		if errLo != nil || errHi != nil {
			return 0, 0, false
		}
		return lo, hi, true
	}
	p, err := strconv.Atoi(tok)
	if err != nil {
		return 0, 0, false
	}
	return p, p, true
}

// portRangeContains reports whether any range covers proto/port.
func portRangeContains(ranges []semanagePortRange, proto string, port int) bool {
	for _, r := range ranges {
		if r.proto == proto && port >= r.lo && port <= r.hi {
			return true
		}
	}
	return false
}

// ── chcon-vs-semanage context detection (§6-add-3) ────────────────────────────

// parseSELinuxContextIssues checks each unique absolute path seen in a
// file/dir-class AVC denial: if its actual context (`ls -Z`) differs from the
// policy default (`matchpathcon -n`) AND no semanage fcontext customization
// covers it, the context was set via `chcon` and will be lost on the next
// relabel. A path whose differing context IS covered by a semanage rule is a
// legitimate, permanent customization and is skipped — not a finding.
func parseSELinuxContextIssues(ctx context.Context, groups []models.SELinuxAVCGroup) []models.SELinuxContextIssue {
	paths := uniqueAVCPaths(groups)
	if len(paths) == 0 {
		return nil
	}
	rules := collectSemanageFcontextRules(ctx)

	var out []models.SELinuxContextIssue
	for _, path := range paths {
		expected := matchpathconContext(ctx, path)
		actual := lsZContext(ctx, path)
		if expected == "" || actual == "" || expected == actual {
			continue
		}
		if fcontextCovers(rules, path, actual) {
			continue
		}
		out = append(out, models.SELinuxContextIssue{
			Path: path, ActualContext: actual, ExpectedContext: expected,
		})
	}
	return out
}

// uniqueAVCPaths flattens and deduplicates the Paths of every group, capped
// at 10 to bound the number of matchpathcon/ls -Z shell-outs.
func uniqueAVCPaths(groups []models.SELinuxAVCGroup) []string {
	seen := map[string]bool{}
	var paths []string
	for _, g := range groups {
		for _, p := range g.Paths {
			if seen[p] {
				continue
			}
			seen[p] = true
			paths = append(paths, p)
			if len(paths) >= 10 {
				return paths
			}
		}
	}
	return paths
}

// matchpathconContext returns the policy-default context for path via
// `matchpathcon -n` (the -n flag prints only the context, no path prefix).
func matchpathconContext(ctx context.Context, path string) string {
	out, err := runCmdTimeout(ctx, 3*time.Second, "matchpathcon", "-n", path)
	if err != nil {
		return ""
	}
	return strings.TrimSpace(out)
}

// lsZContext returns the actual context of path via `ls -dZ` (the -d flag
// stops it from listing a directory's contents instead of the path itself).
func lsZContext(ctx context.Context, path string) string {
	out, err := runCmdTimeout(ctx, 3*time.Second, "ls", "-dZ", path)
	if err != nil {
		return ""
	}
	fields := strings.Fields(out)
	if len(fields) == 0 {
		return ""
	}
	return fields[0]
}

// fcontextRule is one parsed `semanage fcontext -C -l` row.
type fcontextRule struct {
	pattern *regexp.Regexp
	context string
}

// collectSemanageFcontextRules runs `semanage fcontext -C -l` (customizations
// only — policy defaults are what matchpathcon already reports) and returns
// the parsed path-pattern → context rules.
func collectSemanageFcontextRules(ctx context.Context) []fcontextRule {
	out, err := runCmdTimeout(ctx, 5*time.Second, "semanage", "fcontext", "-C", "-l")
	if err != nil {
		return nil
	}
	return parseFcontextRules(out)
}

// parseFcontextRules parses `semanage fcontext -C -l` output, e.g.:
//
//	SELinux fcontext                                  type               Context
//
//	/data/app(/.*)?                                    all files          system_u:object_r:httpd_sys_content_t:s0
//
// The middle "type" column (file/dir/all files/...) can contain spaces, so
// only the first (pattern) and last (context) fields are trusted.
func parseFcontextRules(out string) []fcontextRule {
	var rules []fcontextRule
	for _, line := range strings.Split(out, "\n") {
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		context := fields[len(fields)-1]
		if !strings.Contains(context, ":") {
			continue // header/blank line — not a context
		}
		re, err := regexp.Compile("^" + fields[0] + "$")
		if err != nil {
			continue // an fcontext regex Go's RE2 can't compile — skip rather than false-flag
		}
		rules = append(rules, fcontextRule{pattern: re, context: context})
	}
	return rules
}

// fcontextCovers reports whether any customized fcontext rule matches path
// with the same context TYPE as actual (comparing only the 3rd colon-field —
// user/role/level commonly differ without it being a different customization).
func fcontextCovers(rules []fcontextRule, path, actual string) bool {
	actualType := selinuxContextType(actual)
	for _, r := range rules {
		if r.pattern.MatchString(path) && selinuxContextType(r.context) == actualType {
			return true
		}
	}
	return false
}

// selinuxContextType extracts the type field from a user:role:type:level context.
func selinuxContextType(context string) string {
	parts := strings.Split(context, ":")
	if len(parts) < 3 {
		return ""
	}
	return parts[2]
}

// collectRelevantBooleans runs getsebool -a and filters to booleans related to
// the denied scontexts that are currently OFF.
func collectRelevantBooleans(ctx context.Context, groups []models.SELinuxAVCGroup) []models.SELinuxBoolean {
	out, err := runCmdTimeout(ctx, 5*time.Second, "getsebool", "-a")
	if err != nil {
		return nil
	}

	// Build set of scontext prefixes to search for (e.g. secSvcHTTPD from "httpd_t")
	keywords := make(map[string]bool)
	for _, g := range groups {
		// "httpd_t" → secSvcHTTPD; "container_runtime_t" → secTypeContainer
		stype := strings.TrimSuffix(g.Scontext, "_t")
		if idx := strings.LastIndex(stype, ":"); idx >= 0 {
			stype = stype[idx+1:]
		}
		if stype != "" {
			keywords[stype] = true
		}
	}
	_ = ctx

	var booleans []models.SELinuxBoolean
	seen := make(map[string]bool)
	for _, line := range strings.Split(out, "\n") {
		// Format: "httpd_can_network_connect --> off"
		parts := strings.SplitN(line, " --> ", 2)
		if len(parts) != 2 {
			continue
		}
		name := strings.TrimSpace(parts[0])
		value := strings.TrimSpace(parts[1])
		if value == "on" || seen[name] {
			continue // only surface currently-off booleans
		}
		// Check if name contains any denied scontext keyword
		nameLower := strings.ToLower(name)
		for kw := range keywords {
			if strings.Contains(nameLower, kw) {
				seen[name] = true
				booleans = append(booleans, models.SELinuxBoolean{
					Name:   name,
					Active: false,
					SetCmd: fmt.Sprintf("setsebool -P %s on", name),
				})
				break
			}
		}
		if len(booleans) >= 10 {
			break
		}
	}
	return booleans
}

// collectAppArmorDenials parses journalctl for AppArmor DENIED entries in last 24h.
// collectAppArmorDenials returns the grouped AppArmor denials from the last
// 24h and whether the scan itself was readable. journalctl's own "exit 1,
// zero matches" convention for -g/--grep (see journalclGrepNoMatch's sibling
// use in postboot_linux.go, internal-collectors-26-01) is the routine,
// genuinely clean case — readable stays true. A different failure (spawn
// error, permission denied, an unexpected exit code) means the scan itself
// couldn't run; readable is false so the caller can disclose it instead of
// silently reading identically to "checked, zero denials".
func collectAppArmorDenials(ctx context.Context) (denials []models.AppArmorDenial, readable bool) {
	jCtx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	out, err := runCmd(jCtx, "journalctl", "-t", "kernel", "-g", `apparmor="DENIED"`,
		svcNoPager, "--since", "24 hours ago", "-o", "short")
	if err != nil {
		return nil, journalctlGrepNoMatch(err)
	}
	if strings.TrimSpace(out) == "" {
		return nil, true
	}

	type key struct{ profile, op, path string }
	counts := make(map[key]int)
	for _, line := range strings.Split(out, "\n") {
		if !strings.Contains(line, `apparmor="DENIED"`) {
			continue
		}
		k := key{
			profile: extractAAField(line, "profile="),
			op:      extractAAField(line, "requested_mask="),
			path:    extractAAField(line, "name="),
		}
		counts[k]++
	}

	var groups []models.AppArmorDenial
	for k, c := range counts {
		groups = append(groups, models.AppArmorDenial{
			Profile:   k.profile,
			Operation: k.op,
			Path:      k.path,
			Count:     c,
		})
	}
	// Sort for a DETERMINISTIC order: counts is a Go map, so without a full sort the
	// group order (and thus which groups survive any downstream top-N truncation)
	// varied each run — non-byte-stable replay + spurious `dsd diff` Security deltas
	// on hosts with AppArmor denials. Count desc, then profile/path/op asc to break
	// ties (equal-count entries must still order stably). (Surfaced by the replay
	// hermeticity guard on pve01, 2026-06-18.)
	sort.Slice(groups, func(i, j int) bool {
		if groups[i].Count != groups[j].Count {
			return groups[i].Count > groups[j].Count
		}
		if groups[i].Profile != groups[j].Profile {
			return groups[i].Profile < groups[j].Profile
		}
		if groups[i].Path != groups[j].Path {
			return groups[i].Path < groups[j].Path
		}
		return groups[i].Operation < groups[j].Operation
	})
	return groups, true
}

// extractAAField extracts a quoted or unquoted value for key= from an AppArmor log line.
func extractAAField(line, key string) string {
	idx := strings.Index(line, key)
	if idx < 0 {
		return ""
	}
	rest := line[idx+len(key):]
	if strings.HasPrefix(rest, `"`) {
		end := strings.Index(rest[1:], `"`)
		if end >= 0 {
			return rest[1 : end+1]
		}
	}
	// Unquoted — ends at space
	fields := strings.Fields(rest)
	if len(fields) > 0 {
		return fields[0]
	}
	return ""
}

// collectPAMLockedAccounts checks for accounts locked by pam_faillock.
func collectPAMLockedAccounts(ctx context.Context) []string {
	fCtx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	out, err := runCmd(fCtx, "faillock", "--user", "")
	if err != nil {
		return nil
	}
	var locked []string
	for _, line := range strings.Split(out, "\n") {
		// Lines with [Locked] marker
		if strings.Contains(line, "[Locked]") {
			fields := strings.Fields(line)
			if len(fields) > 0 {
				locked = append(locked, fields[0])
			}
		}
	}
	return locked
}

// parseUID0Users scans /etc/passwd for non-root accounts with UID 0.
// Only root should have UID 0. Any other UID-0 account is a critical finding.
func parseUID0Users(info *models.SecurityInfo) {
	data, err := readFile("/etc/passwd") // #nosec G304
	if err != nil {
		return
	}
	for _, line := range strings.Split(string(data), "\n") {
		fields := strings.SplitN(line, ":", 4)
		if len(fields) < 4 {
			continue
		}
		user := fields[0]
		uid := fields[2]
		if uid == "0" && user != "root" && user != "" {
			info.UID0Users = append(info.UID0Users, user)
		}
	}
}

// parseSuspectCrons scans cron directories for entries that write to sensitive paths.
// Cron injection is a common persistence technique — writing to /etc, /usr, /tmp
// or piping to bash from a cron job is a red flag.
func parseSuspectCrons(info *models.SecurityInfo) {
	cronDirs := []string{
		"/etc/cron.d",
		"/etc/cron.daily",
		"/etc/cron.weekly",
		"/etc/cron.monthly",
		"/var/spool/cron/crontabs",
	}
	suspectPatterns := []string{
		"| bash", "| sh", "|bash", "|sh",
		"wget ", "curl ", // downloading and executing
		"> /etc/", "> /usr/", // writing to system dirs
		"/tmp/", "/var/tmp/", // writing to world-writable
		"chmod +s", "chmod 4", // setting SUID
	}

	for _, dir := range cronDirs {
		entries, err := readDirEntries(dir)
		if err != nil {
			continue
		}
		for _, e := range entries {
			if e.IsDir() {
				continue
			}
			path := filepath.Join(dir, e.Name())
			data, err := readFile(filepath.Clean(path)) // #nosec G304 -- hardcoded dirs
			if err != nil {
				continue
			}
			for _, line := range strings.Split(string(data), "\n") {
				line = strings.TrimSpace(line)
				if strings.HasPrefix(line, "#") || line == "" {
					continue
				}
				for _, pat := range suspectPatterns {
					if strings.Contains(line, pat) {
						entry := fmt.Sprintf("%s: %s", e.Name(), truncate(line, 80))
						info.SuspectCrons = append(info.SuspectCrons, entry)
						break
					}
				}
			}
		}
	}
}

// truncate shortens a string to maxLen characters.
func truncate(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen] + "…"
}

// wellKnownPortName returns a friendly service name for ports commonly
// activated via systemd socket activation where the process shows as 'systemd'.
func wellKnownPortName(port int) string {
	names := map[int]string{
		25:    "postfix", // SMTP — default MTA on openSUSE/SLES server
		9090:  "cockpit", // RHEL/Rocky web console
		9100:  "node-exporter",
		10250: "kubelet",
		10255: "kubelet-ro",
		2379:  "etcd",
		2380:  "etcd-peer",
		6443:  "kube-apiserver",
	}
	return names[port]
}

// parseFirewall detects the active firewall type and collects key state.
// Checks firewalld, ufw, nftables, and iptables in priority order.
func parseFirewall(ctx context.Context, info *models.SecurityInfo) {
	// firewalld — RHEL/Rocky/Fedora/CentOS default
	if detectFirewalld(ctx, info) {
		return
	}
	// ufw — Ubuntu/Debian common choice
	if detectUFW(ctx, info) {
		return
	}
	// nftables — bare nftables without a management daemon
	if detectNFTables(ctx, info) {
		return
	}
	// iptables — legacy, common on older systems
	if detectIPTables(ctx, info) {
		return
	}
	// No firewall detected — not an error, just record it
	info.FirewallActive = false
	info.SSHAllowed = true // no firewall = everything reachable
}

func detectFirewalld(ctx context.Context, info *models.SecurityInfo) bool {
	out, err := runCmd(ctx, secFwFirewallCmd, "--state")
	if err != nil || strings.TrimSpace(out) != "running" {
		return false
	}
	info.FirewallActive = true
	info.FirewallType = "firewalld"

	// Active zone
	if zoneOut, err := runCmd(ctx, secFwFirewallCmd, "--get-default-zone"); err == nil {
		info.FirewallZone = strings.TrimSpace(zoneOut)
	}

	// Allowed services in active zone
	rulesRead := false
	if svcOut, err := runCmd(ctx, secFwFirewallCmd, "--list-services"); err == nil {
		rulesRead = true
		info.FirewallServices = append(info.FirewallServices, strings.Fields(svcOut)...)
	}

	// SSH allowed?
	info.SSHAllowed = false
	for _, svc := range info.FirewallServices {
		if svc == secSvcSSH {
			info.SSHAllowed = true
			break
		}
	}
	// Also check explicit port 22
	if !info.SSHAllowed {
		if portsOut, err := runCmd(ctx, secFwFirewallCmd, "--list-ports"); err == nil {
			rulesRead = true
			if strings.Contains(portsOut, "22/tcp") {
				info.SSHAllowed = true
			}
		}
	}
	// If neither the service nor the port query succeeded, SSH reachability is
	// unknown — don't claim it's blocked (a false "you may lose remote access"
	// WARN). Matches the conservative default in the nftables path.
	if !rulesRead {
		info.SSHAllowed = true
	}
	return true
}

func detectUFW(ctx context.Context, info *models.SecurityInfo) bool {
	out, err := runCmd(ctx, "ufw", secFldStatus)
	if err != nil {
		return false
	}
	lower := strings.ToLower(out)
	// "Status: inactive" contains secValActive as substring — check for "status: active" specifically
	if !strings.Contains(lower, "status: active") {
		return false
	}
	info.FirewallActive = true
	info.FirewallType = "ufw"
	info.SSHAllowed = sshAllowedUFW(out, sshPort(info))
	return true
}

// sshAllowedUFW reports whether `ufw status` output allows inbound SSH on port.
// ufw's "To" column is the rule target (e.g. "22/tcp", "22/tcp (v6)", "OpenSSH").
// We match the port against THAT column only — checking the whole line for "22"
// (the previous implementation) false-matched "2222/tcp", a source IP ending in
// .22, etc., and treated any "allow" anywhere as allowing SSH. ufw's default
// incoming policy is deny, so SSH is reachable only via an explicit allow/limit
// rule — mirrors the nft/iptables paths (decideSSHAllowed with a drop baseline).
func sshAllowedUFW(out string, port int) bool {
	p := strconv.Itoa(port)
	var acceptSSH, blockSSH bool
	scanner := bufio.NewScanner(strings.NewReader(out))
	for scanner.Scan() {
		raw := scanner.Text()
		fields := strings.Fields(raw)
		if len(fields) < 2 {
			continue
		}
		to := fields[0] // the "To" column: the rule's destination
		matchesSSH := to == p || strings.HasPrefix(to, p+"/") ||
			strings.EqualFold(to, secSvcSSH) || strings.EqualFold(to, "openssh")
		if !matchesSSH {
			continue
		}
		low := strings.ToLower(raw)
		switch {
		case strings.Contains(low, "allow"), strings.Contains(low, "limit"):
			acceptSSH = true
		case strings.Contains(low, "deny"), strings.Contains(low, "reject"):
			blockSSH = true
		}
	}
	return decideSSHAllowed(acceptSSH, blockSSH, true)
}

// detectNFTables reports whether an active nftables ruleset is present.
//
// It queries the LIVE ruleset via `nft list ruleset` (reusing the health
// collector's parser so the two commands agree on what counts as a rule).
// This is what catches systems like NixOS, where the firewall is generated
// into transient rules and never written to /etc/nftables.conf. The on-disk
// config-file probe remains only as a fallback for when the nft binary is
// unavailable on PATH.
func detectNFTables(ctx context.Context, info *models.SecurityInfo) bool {
	// The sbin-aware gate matters for non-root runs: nft lives in /sbin or
	// /usr/sbin, off a typical non-root $PATH, so a plain lookPath would miss it
	// and we'd wrongly fall through to the config probe / "none detected". runCmd
	// is invoked by BARE name (not the resolved path) to keep the capture/replay
	// key stable; on a non-root run the bare-name exec fails to launch, which we
	// treat as unreadable below.
	if sbinToolPath("nft") != "" {
		out, err := runCmd(ctx, "nft", "list", "ruleset")
		if err != nil {
			// nft installed but the ruleset is unreadable (non-root EPERM, or the
			// binary is off a non-root $PATH). State unknown — record it so the
			// renderer says "not verified" instead of a clean-looking "none
			// detected", and do NOT fall through to the on-disk-config probe: the
			// binary IS present, so inferring secValActive from a config file we can't
			// confirm is loaded would be a false-OK.
			info.FirewallUnreadable = true
			if info.FirewallType == "" {
				info.FirewallType = secFwNFTables
			}
			return false
		}
		fw := &models.FirewallInfo{}
		parseNFTRuleset(out, fw)
		if fw.TotalRules > 0 {
			info.FirewallActive = true
			info.FirewallType = secFwNFTables
			info.SSHAllowed = sshAllowedNFT(out, sshPort(info))
			return true
		}
		// nft is installed but the ruleset is empty — tooling present, host
		// unprotected. Record it (renderer mirrors the health Firewall WARN) and
		// return: an empty LIVE ruleset is authoritative, so don't let the on-disk
		// config probe upgrade this to a misleading secValActive.
		info.FirewallToolingPresent = true
		if info.FirewallType == "" {
			info.FirewallType = secFwNFTables
		}
		return false
	}
	// Fallback: nft binary not found on $PATH or in sbin — infer from on-disk
	// config. We can't read the ruleset here, so leave SSH reachability
	// conservatively secValAllowed.
	entries, _ := glob("/etc/nftables.conf")
	if len(entries) == 0 {
		entries, _ = glob("/etc/nftables.d/*.nft")
	}
	if len(entries) > 0 {
		// internal-collectors-29-03: config-file PRESENCE does not prove a
		// ruleset is actually loaded — the nft binary itself is absent here, so
		// we can't even attempt to confirm it. This is exactly the false-OK the
		// live-ruleset rewrite above exists to prevent for the tool-present
		// case; the tool-absent fallback re-introduced it by claiming
		// FirewallActive from file presence alone. Disclose unverified instead,
		// and return false (not true) so the chain below still checks iptables
		// — the real active backend might not be nftables at all.
		info.FirewallConfigOnlyUnverified = true
		info.FirewallType = secFwNFTables
	}
	return false
}

// detectIPTables reports whether iptables has a non-trivial ruleset.
//
// It runs `iptables -L` via the health collector's parser rather than reading
// /proc/net/ip_tables_names. On nftables-backend systems (NixOS, modern
// distros) the legacy ip_tables kernel module is never loaded, so that proc
// file is absent even though the iptables-nft wrapper can list a full ruleset.
func detectIPTables(ctx context.Context, info *models.SecurityInfo) bool {
	if sbinToolPath(secFwIPTables) == "" { // sbin-aware gate (see detectNFTables)
		return false
	}
	// Bare name keeps the replay key stable (see detectNFTables); a non-root
	// launch failure is treated as unreadable below.
	out, err := runCmd(ctx, secFwIPTables, "-L", "-n", "--line-numbers")
	if err != nil {
		// iptables installed but unreadable (non-root EPERM) — state unknown.
		info.FirewallUnreadable = true
		if info.FirewallType == "" {
			info.FirewallType = secFwIPTables
		}
		return false
	}
	fw := &models.FirewallInfo{}
	parseIPTList(out, fw)
	if fw.TotalRules > 0 {
		info.FirewallActive = true
		info.FirewallType = secFwIPTables
		info.SSHAllowed = sshAllowedIPT(out, sshPort(info))
		return true
	}
	// iptables installed but no rules — tooling present, host unprotected. Only
	// claim the backend name if nft didn't already (nft is the modern default).
	info.FirewallToolingPresent = true
	if info.FirewallType == "" {
		info.FirewallType = secFwIPTables
	}
	return false
}

// sshPort returns the SSH port to look for in firewall rules: the configured
// non-standard port if known, else the default 22.
func sshPort(info *models.SecurityInfo) int {
	if info.SSHPort > 0 {
		return info.SSHPort
	}
	return 22
}

// sshAllowedNFT decides whether an nftables ruleset admits NEW inbound SSH on
// the given port. It is a heuristic matching the coarseness of the
// firewalld/ufw service checks, and biases toward secValAllowed: it reports blocked
// only when the input hook defaults to drop with no matching accept, or no
// accept exists and the port is explicitly dropped/rejected. Stateful and
// interface rules (ct state, iifname lo) don't admit new SSH and are ignored.
func sshAllowedNFT(out string, port int) bool {
	portWord := regexp.MustCompile(fmt.Sprintf(`\b%d\b`, port))
	var inputPolicyDrop, acceptSSH, blockSSH bool
	scanner := bufio.NewScanner(strings.NewReader(out))
	for scanner.Scan() {
		low := strings.ToLower(strings.TrimSpace(scanner.Text()))
		if strings.Contains(low, "hook input") && strings.Contains(low, "policy drop") {
			inputPolicyDrop = true
		}
		if !strings.Contains(low, "dport") {
			continue
		}
		if !portWord.MatchString(low) && !strings.Contains(low, secSvcSSH) {
			continue
		}
		switch {
		case strings.Contains(low, "accept"):
			acceptSSH = true
		case strings.Contains(low, "drop"), strings.Contains(low, "reject"):
			blockSSH = true
		}
	}
	return decideSSHAllowed(acceptSSH, blockSSH, inputPolicyDrop)
}

// sshAllowedIPT decides whether the iptables ruleset admits new inbound SSH.
// Operates on `iptables -L -n --line-numbers` output (the --line-numbers prefix
// is stripped via field parsing). Same heuristic and bias as sshAllowedNFT.
func sshAllowedIPT(out string, port int) bool {
	portWord := regexp.MustCompile(fmt.Sprintf(`\b%d\b`, port))
	var inputPolicyDrop, acceptSSH, blockSSH bool
	scanner := bufio.NewScanner(strings.NewReader(out))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if strings.HasPrefix(line, "Chain INPUT") && strings.Contains(line, "policy DROP") {
			inputPolicyDrop = true
			continue
		}
		if strings.HasPrefix(line, "Chain ") {
			continue
		}
		low := strings.ToLower(line)
		if !strings.Contains(low, "dpt:") && !strings.Contains(low, "dpts:") && !strings.Contains(low, "dports") {
			continue
		}
		if !portWord.MatchString(low) && !strings.Contains(low, ":ssh") {
			continue
		}
		fields := strings.Fields(line)
		target := fields[0]
		if _, err := strconv.Atoi(fields[0]); err == nil && len(fields) > 1 {
			target = fields[1] // strip leading --line-numbers column
		}
		switch target {
		case "ACCEPT":
			acceptSSH = true
		case "DROP", "REJECT":
			blockSSH = true
		}
	}
	return decideSSHAllowed(acceptSSH, blockSSH, inputPolicyDrop)
}

// decideSSHAllowed applies the shared decision, biased toward secValAllowed: an
// explicit accept anywhere wins (covers accept-from-subnet); otherwise an
// explicit block or a default-drop input policy means blocked; absent any
// filtering signal, assume reachable.
func decideSSHAllowed(acceptSSH, blockSSH, inputPolicyDrop bool) bool {
	switch {
	case acceptSSH:
		return true
	case blockSSH:
		return false
	case inputPolicyDrop:
		return false
	default:
		return true
	}
}

// parseRHELSecurity collects security state specific to RHEL/Rocky/Fedora:
// FIPS mode, crypto-policies, USBGuard, AIDE, and auditd rules.
func parseRHELSecurity(ctx context.Context, info *models.SecurityInfo) {
	parseFIPS(info)
	parseCryptoPolicy(ctx, info)
	parseUSBGuard(info)
	parseAIDE(info)
	parseAuditRules(ctx, info)
}

// parseFIPS checks /proc/sys/crypto/fips_enabled.
// Returns silently on non-RHEL systems where the file doesn't exist.
func parseFIPS(info *models.SecurityInfo) {
	data, err := readFile("/proc/sys/crypto/fips_enabled") // #nosec G304
	if err != nil {
		return
	}
	info.FIPSEnabled = strings.TrimSpace(string(data)) == "1"
}

// parseCryptoPolicy reads the active system-wide cryptographic policy.
// RHEL/Rocky uses /etc/crypto-policies/config (DEFAULT, LEGACY, FUTURE, FIPS).
func parseCryptoPolicy(ctx context.Context, info *models.SecurityInfo) {
	// Prefer reading the config file directly — no subprocess needed
	if data, err := readFile("/etc/crypto-policies/config"); err == nil { // #nosec G304
		policy := strings.TrimSpace(string(data))
		if policy != "" {
			info.CryptoPolicy = policy
			return
		}
	}
	// Fallback: update-crypto-policies --show (Fedora may need this)
	if out, err := runCmd(ctx, "update-crypto-policies", "--show"); err == nil {
		info.CryptoPolicy = strings.TrimSpace(out)
	}
}

// parseUSBGuard checks if usbguard service is active.
func parseUSBGuard(info *models.SecurityInfo) {
	data, err := readFile("/sys/class/usb_device") // #nosec G304
	_ = data
	// usbguard detection: check if the service unit exists and is active
	if fileExists("/usr/sbin/usbguard") {
		// Binary present — check if service is active via systemd cgroup
		if fileExists("/sys/fs/cgroup/system.slice/usbguard.service") {
			info.USBGuardActive = true
			return
		}
	}
	_ = err
	// Fallback: check pid file or socket
	if fileExists("/run/usbguard/usbguard-daemon.pid") {
		info.USBGuardActive = true
	}
}

// parseAIDE checks if AIDE is installed and when the database was last updated.
func parseAIDE(info *models.SecurityInfo) {
	// Check binary
	aidePaths := []string{"/usr/sbin/aide", "/usr/bin/aide"}
	for _, p := range aidePaths {
		if fileExists(p) {
			info.AIDEInstalled = true
			break
		}
	}
	if !info.AIDEInstalled {
		return
	}

	// Check database existence
	dbPaths := []string{
		"/var/lib/aide/aide.db",
		"/var/lib/aide/aide.db.gz",
		"/var/lib/aide/aide.db.new",
	}
	for _, p := range dbPaths {
		fi, err := statFile(p)
		if err == nil {
			info.AIDEDBExists = true
			days := int(time.Since(fi.ModTime).Hours() / 24)
			info.AIDELastRunDays = days
			return
		}
		// Permission-denied (non-root) means the database might actually exist —
		// distinct from a genuine ENOENT, which means it was truly never
		// initialised. Flag it so the analysis layer doesn't tell the operator
		// to `aide --init` over a database it never actually looked at.
		if os.IsPermission(err) {
			info.AIDEDBUnreadable = true
		}
	}
	info.AIDELastRunDays = -1 // installed but never run (or unreadable — see AIDEDBUnreadable)
}

// parseAuditRules counts active auditd rules via auditctl.
// Returns -1 when auditctl is unavailable or auditd not running. `auditctl -l`
// is root-only — on EACCES (auditd installed and running, just unreadable by
// this user) it sets AuditRulesUnreadable instead, so a genuine "not installed"
// isn't confused with "couldn't check because we're not root".
func parseAuditRules(ctx context.Context, info *models.SecurityInfo) {
	out, err := runCmdCombined(ctx, "auditctl", "-l")
	info.AuditRules, info.AuditRulesUnreadable = auditRulesFromOutput(out, err)
}

// auditRulesFromOutput decides the AuditRules count (or -1) and whether the
// -1 means "genuinely not installed/running" vs "installed and running but
// this (non-root) user was refused" from `auditctl -l`'s combined
// stdout+stderr and exit error. Split out from parseAuditRules so the decision
// logic is unit-testable without running the real command.
func auditRulesFromOutput(out string, err error) (rules int, unreadable bool) {
	if err != nil {
		return -1, strings.Contains(strings.ToLower(out), "must be root")
	}
	// "No rules" means auditd running but empty ruleset
	if strings.Contains(out, "No rules") || strings.TrimSpace(out) == "" {
		return 0, false
	}
	count := 0
	for _, line := range strings.Split(out, "\n") {
		line = strings.TrimSpace(line)
		if line != "" && !strings.HasPrefix(line, "#") {
			count++
		}
	}
	return count, false
}

// parseSupportconfig detects SUSE's supportconfig diagnostic tool.
// supportutils package provides /usr/sbin/supportconfig.
// Archives are saved to /var/log/ as nts_HOST_DATE.tbz or scc_HOST_DATE.txz.
func parseSupportconfig(info *models.SecurityInfo) {
	// Check binary exists
	paths := []string{"/usr/sbin/supportconfig", "/sbin/supportconfig"}
	for _, p := range paths {
		if fileExists(p) {
			info.SupportconfigAvailable = true
			break
		}
	}
	if !info.SupportconfigAvailable {
		return
	}

	// Find most recent archive in /var/log/
	// SLES 16 creates directories (scc_HOST_DATE/) not archives
	patterns := []string{
		"/var/log/scc_*.txz", // SLES 15+/16 archive format
		"/var/log/nts_*.tbz", // older SLES format
		"/tmp/scc_*.txz",
		"/tmp/nts_*.tbz",
	}

	var newestMod time.Time
	var newestPath string

	// Also check for directory-based output (SLES 16 default). statFile (not
	// e.Info(), whose source-fake FileInfo carries a zero ModTime) so the
	// directory's real mtime participates in the newest-wins comparison.
	entries, err := readDirEntries("/var/log")
	if err == nil {
		for _, e := range entries {
			if e.IsDir() && (strings.HasPrefix(e.Name(), "scc_") || strings.HasPrefix(e.Name(), "nts_")) {
				p := "/var/log/" + e.Name()
				if fi, err := statFile(p); err == nil && (newestPath == "" || fi.ModTime.After(newestMod)) {
					newestMod = fi.ModTime
					newestPath = p
				}
			}
		}
	}
	// Permission-denied (non-root) listing /var/log means archives may exist
	// but couldn't be enumerated — distinct from a genuine "never run". Flagged
	// below only if the search ultimately turns up nothing, since a match found
	// via another path (e.g. /tmp) still counts as a real answer.
	logDirUnreadable := err != nil && os.IsPermission(err)

	for _, pattern := range patterns {
		matches, err := glob(pattern)
		if err != nil {
			continue
		}
		for _, match := range matches {
			// Skip .md5 checksum files
			if strings.HasSuffix(match, ".md5") {
				continue
			}
			fi, err := statFile(match)
			if err != nil {
				continue
			}
			if newestPath == "" || fi.ModTime.After(newestMod) {
				newestMod = fi.ModTime
				newestPath = match
			}
		}
	}

	if newestPath == "" {
		info.SupportconfigLastRunDays = -1 // never run (or unreadable — see SupportconfigUnreadable)
		if logDirUnreadable {
			info.SupportconfigUnreadable = true
		}
		return
	}

	info.SupportconfigArchive = newestPath
	info.SupportconfigLastRunDays = int(time.Since(newestMod).Hours() / 24)
}

// parseAppArmor populates AppArmor state into SecurityInfo.
// Reuses the same detection logic as KernelSecurityCollector.
func parseAppArmor(info *models.SecurityInfo) {
	if !apparmorEnabled() {
		return
	}
	info.AppArmorMode = apparmorMode()
	total, _, complain := apparmorDetail()
	info.AppArmorProfiles = total
	info.AppArmorComplain = complain
	info.AppArmorDenials = countAppArmorDenials(1 * time.Hour)
}

// parseSUSEConnect reads SUSEConnect registration + subscription expiry.
// `SUSEConnect --status` returns JSON like:
// [{secFldIdentifier:"SLES",secFldStatus:"Registered",secFldSubscription:"ACTIVE",
//
//	secFldExpiresAt:"2026-07-13 00:00:00 UTC","type":"evaluation",...}]
func parseSUSEConnect(ctx context.Context, info *models.SecurityInfo) {
	CollectSUSEConnect(ctx, info)
}

// CollectSUSEConnect populates SUSEConnect subscription fields into info.
// Exported so SUSEConnectCollector can call it directly without duplicating logic.
func CollectSUSEConnect(ctx context.Context, info *models.SecurityInfo) {
	if _, err := lookPath("SUSEConnect"); err != nil {
		return
	}
	out, err := runCmd(ctx, "SUSEConnect", "--status")
	if err != nil || strings.TrimSpace(out) == "" {
		// SUSEConnect present but the status query failed (network/SCC error, proxy,
		// transient) — registration is UNVERIFIED, not "unregistered". Flag it so the
		// verdict says "not verified" instead of a confident "not registered" WARN.
		info.SUSEConnectStatus = "query-failed"
		return
	}

	applySUSEConnectStatus(out, info)
}

// applySUSEConnectStatus parses `SUSEConnect --status` JSON into info. The output is
// an array, one entry per product, e.g.
//
//	[{secFldIdentifier:"SLES",secFldStatus:"Registered",secFldSubscription:"ACTIVE",
//	  secFldExpiresAt:"2026-07-13 00:00:00 UTC"}]
//
// An UNREGISTERED host returns status:"Not Registered" (verified live on openSUSE
// Leap). The old code matched the substring "registered" — which is INSIDE "Not
// Registered" — so an unregistered host read as REGISTERED (a silent false-OK, and a
// false "EXPIRED" CRIT on the security path). We parse the JSON and compare exactly.
// Split out so it is unit-testable against real command output.
func applySUSEConnectStatus(out string, info *models.SecurityInfo) {
	var products []struct {
		Identifier         string `json:"identifier"`
		Status             string `json:"status"`
		SubscriptionStatus string `json:"subscription_status"`
		ExpiresAt          string `json:"expires_at"`
	}
	if err := json.Unmarshal([]byte(out), &products); err != nil {
		info.SUSEConnectStatus = "query-failed" // unparseable — can't determine registration
		return
	}

	info.SUSEConnectExpiresDays = -1 // unknown until a registered product reports expiry
	for _, p := range products {
		if !strings.EqualFold(strings.TrimSpace(p.Status), "registered") {
			continue
		}
		info.SUSEConnectRegistered = true
		if p.SubscriptionStatus != "" {
			info.SUSEConnectStatus = p.SubscriptionStatus
		}
		if days, ok := parseSUSEExpiry(p.ExpiresAt); ok {
			info.SUSEConnectExpiresDays = days
		}
	}
}

// parseSUSEExpiry parses a SUSEConnect secFldExpiresAt timestamp ("2026-07-13 00:00:00
// UTC") into whole days remaining (0 = already expired). ok is false when the field
// is empty or unparseable, so the caller leaves ExpiresDays at -1 (unknown).
func parseSUSEExpiry(expiresAt string) (days int, ok bool) {
	expiresAt = strings.TrimSpace(expiresAt)
	if expiresAt == "" {
		return 0, false
	}
	t, err := time.Parse("2006-01-02 15:04:05 MST", expiresAt)
	if err != nil {
		return 0, false
	}
	days = int(time.Until(t).Hours() / 24)
	if days < 0 {
		days = 0 // expired
	}
	return days, true
}

// isOffensiveDistro returns true for pentest/offensive security distros
// that ship with intentionally relaxed security defaults (root SSH, no firewall).
// Used to suppress false-positive WARNs in dsd security. Uses the platform
// Profile when set, falling back to the inline os-release read otherwise.
func (c *SecurityCollector) isOffensiveDistro() bool {
	if c.profile.Distro != "" {
		d := c.profile.Distro
		return d == "kali" || d == "parrot" || strings.Contains(d, "blackarch")
	}
	return isOffensiveDistro()
}

// isOffensiveDistro is the zero-profile fallback: a direct os-release read.
func isOffensiveDistro() bool {
	data, err := readFile("/etc/os-release") // #nosec G304
	if err != nil {
		return false
	}
	lower := strings.ToLower(string(data))
	// Kali Linux: ID=kali, ID_LIKE=debian
	// Parrot OS: ID=parrot
	// BlackArch: uses Arch base but NAME contains BlackArch
	return strings.Contains(lower, `id="kali"`) ||
		strings.Contains(lower, "id=kali") ||
		strings.Contains(lower, `id="parrot"`) ||
		strings.Contains(lower, "id=parrot") ||
		strings.Contains(lower, "blackarch")
}

// parsePasswordAging reads /etc/shadow (root only) to detect:
// 1. Accounts with an empty password field (no password set) — CRIT
// 2. Human accounts (UID ≥ 1000) with Maximum_days=99999 (password never expires) — WARN
//
// /etc/shadow format: user:password:lastchg:min:max:warn:inactive:expire:reserved
// password="" → empty password
// max field = 99999 or 0 → password never expires
func parsePasswordAging(info *models.SecurityInfo) {
	shadow, err := readFile("/etc/shadow") // #nosec G304 -- hardcoded system file, root only
	if err != nil {
		// Present-but-unreadable (non-root) → flag it so the verdict says "not
		// audited" instead of silently reporting no empty/stale-password accounts.
		// A genuinely absent /etc/shadow (rare) just means nothing to audit.
		if os.IsPermission(err) {
			info.ShadowUnreadable = true
		}
		return
	}

	// Build UID lookup from /etc/passwd to filter human accounts
	humanAccounts := map[string]bool{}
	if passwd, err := readFile("/etc/passwd"); err == nil { // #nosec G304
		for _, line := range strings.Split(string(passwd), "\n") {
			fields := strings.SplitN(line, ":", 4)
			if len(fields) < 4 {
				continue
			}
			uid, _ := strconv.Atoi(fields[2])
			if uid >= 1000 && uid < 65534 {
				humanAccounts[fields[0]] = true
			}
		}
	}

	for _, line := range strings.Split(string(shadow), "\n") {
		fields := strings.SplitN(line, ":", 9)
		if len(fields) < 3 {
			continue
		}
		user := fields[0]
		pwField := fields[1]
		if user == "" {
			continue
		}

		// Empty password — account has no password protection
		if pwField == "" {
			info.EmptyPasswordAccounts = append(info.EmptyPasswordAccounts, user)
		}

		// Password expiry check — only for human accounts
		if humanAccounts[user] && len(fields) >= 5 {
			maxDays := fields[4]
			if maxDays == "99999" || maxDays == "0" {
				info.StalePasswordAccounts = append(info.StalePasswordAccounts, user)
			}
		}
	}
}

// parseWorldWritable checks /tmp, /var/tmp, and /dev/shm for missing sticky bits.
// World-writable directories without sticky bit allow any user to delete others' files —
// a classic privilege escalation vector (e.g. tmp symlink attacks).
func parseWorldWritable(info *models.SecurityInfo) {
	dirs := []string{"/tmp", "/var/tmp", "/dev/shm"}
	for _, dir := range dirs {
		fi, err := statFile(dir)
		if err != nil {
			continue
		}
		mode := fi.Mode
		// World-writable = mode has o+w set (0002)
		// Sticky bit = mode has sticky bit (01000 in octal)
		worldWritable := mode&0002 != 0
		stickyBit := mode&os.ModeSticky != 0
		if worldWritable && !stickyBit {
			info.WorldWritableDirs = append(info.WorldWritableDirs, dir)
		}
	}
}

// ── SELinux AVC disambiguation ────────────────────────────────────────────────

// parseAVCGroups reads /var/log/audit/audit.log and groups AVC denials by
// (scontext_type, tcontext_type, tclass) — the unit an admin acts on.
// For each group it attempts to find a getsebool fix or semanage/chcon command.
// avcGroupKey identifies one denial pattern (source type, target type, target class).
type avcGroupKey struct{ stype, ttype, tclass string }

// avcGroupData accumulates the permissions, paths, and count for one avcGroupKey.
type avcGroupData struct {
	perms map[string]bool
	paths map[string]bool
	count int
}

func parseAVCGroups(ctx context.Context, window time.Duration) []models.SELinuxAVCGroup {
	f, err := openFile("/var/log/audit/audit.log") // #nosec G304 -- hardcoded audit log path
	if err != nil {
		return nil
	}
	defer f.Close() //nolint:errcheck

	groups := map[avcGroupKey]*avcGroupData{}
	cutoff := time.Now().Add(-window)

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		scanAVCLine(scanner.Text(), groups, cutoff)
	}
	if err := scanner.Err(); err != nil {
		_ = err // best-effort; process denials collected so far
	}

	if len(groups) == 0 {
		return nil
	}
	return buildSELinuxAVCGroups(ctx, groups)
}

// scanAVCLine parses one audit.log line and, if it is an enforced AVC denial
// within the window, folds it into groups keyed by (scontext, tcontext, tclass).
func scanAVCLine(line string, groups map[avcGroupKey]*avcGroupData, cutoff time.Time) {
	if !strings.Contains(line, "type=AVC") {
		return
	}
	// Enforced denials only — a permissive=1 record was logged but not blocked,
	// so it must not appear among the grouped findings the Hardening verdict
	// surfaces (consistent with the denial COUNT, which also excludes it).
	if avcIsPermissive(line) {
		return
	}
	// Timestamp check
	if idx := strings.Index(line, "msg=audit("); idx >= 0 {
		rest := line[idx+10:]
		if dot := strings.IndexByte(rest, '.'); dot > 0 {
			if sec, err := strconv.ParseInt(rest[:dot], 10, 64); err == nil {
				if !time.Unix(sec, 0).After(cutoff) {
					return
				}
			}
		}
	}

	stype := avcField(line, "scontext=")
	ttype := avcField(line, "tcontext=")
	tclass := avcField(line, "tclass=")
	perms := avcPerms(line)

	if stype == "" || ttype == "" || tclass == "" {
		return
	}
	// Keep only the type component (last part of user:role:type:level)
	stype = lastPart(stype, ":")
	ttype = lastPart(ttype, ":")

	key := avcGroupKey{stype, ttype, tclass}
	if _, ok := groups[key]; !ok {
		groups[key] = &avcGroupData{perms: map[string]bool{}, paths: map[string]bool{}}
	}
	for _, p := range perms {
		groups[key].perms[p] = true
	}
	// name= is only reliably a full path for file/dir-class denials, and even
	// then not always absolute (the audit record alone doesn't always resolve
	// it) — only track it when it is, so the chcon check never runs against a
	// guessed/relative path (§6-add-3).
	if tclass == secTypeFile || tclass == "dir" {
		if name := strings.Trim(avcField(line, "name="), `"`); strings.HasPrefix(name, "/") {
			groups[key].paths[name] = true
		}
	}
	groups[key].count++
}

// buildSELinuxAVCGroups turns the accumulated groups map into the sorted,
// top-10-capped result slice, resolving a boolean/semanage fix for each group.
func buildSELinuxAVCGroups(ctx context.Context, groups map[avcGroupKey]*avcGroupData) []models.SELinuxAVCGroup {
	result := make([]models.SELinuxAVCGroup, 0, len(groups))
	for key, data := range groups {
		perms := make([]string, 0, len(data.perms))
		for p := range data.perms {
			perms = append(perms, p)
		}
		sort.Strings(perms) // data.perms is a map — sort for a stable perm order under replay
		paths := make([]string, 0, len(data.paths))
		for p := range data.paths {
			paths = append(paths, p)
		}
		sort.Strings(paths) // data.paths is a map — sort for stable order under replay
		g := models.SELinuxAVCGroup{
			Scontext: key.stype,
			Tcontext: key.ttype,
			Tclass:   key.tclass,
			Perms:    perms,
			Count:    data.count,
			Paths:    paths,
		}
		// Try to find a boolean fix or semanage command
		g.BooleanFix, g.FixCmd = suggestSELinuxFix(ctx, key.stype, key.ttype, key.tclass, perms)
		result = append(result, g)
	}
	// Sort by count descending, most frequent first. The scontext/tcontext/tclass
	// tiebreakers are essential: groups is a Go map, so a count-only sort left
	// equal-count groups in random iteration order — non-byte-stable replay + a
	// flaky top-10 cut. (Surfaced by the replay hermeticity guard, 2026-06-18.)
	sort.Slice(result, func(i, j int) bool {
		if result[i].Count != result[j].Count {
			return result[i].Count > result[j].Count
		}
		if result[i].Scontext != result[j].Scontext {
			return result[i].Scontext < result[j].Scontext
		}
		if result[i].Tcontext != result[j].Tcontext {
			return result[i].Tcontext < result[j].Tcontext
		}
		return result[i].Tclass < result[j].Tclass
	})
	// Cap at top 10 groups
	if len(result) > 10 {
		result = result[:10]
	}
	return result
}

// avcField extracts a field value from an AVC log line.
// e.g. avcField(line, "scontext=") returns "system_u:system_r:init_t:s0"
func avcField(line, key string) string {
	idx := strings.Index(line, key)
	if idx < 0 {
		return ""
	}
	rest := line[idx+len(key):]
	// Value ends at next space
	if end := strings.IndexByte(rest, ' '); end > 0 {
		return rest[:end]
	}
	return rest
}

// avcPerms extracts the list of denied permissions from an AVC line.
// Format: "{ read write open }" or "{ prog_run }"
func avcPerms(line string) []string {
	start := strings.Index(line, "{ ")
	end := strings.Index(line, " }")
	if start < 0 || end < 0 || end <= start {
		return nil
	}
	inner := line[start+2 : end]
	return strings.Fields(inner)
}

// lastPart extracts the SELinux type from a context string. Contexts are
// user:role:type[:level[:categories]], so the type is the third colon-delimited
// field. "system_u:system_r:init_t:s0" → "init_t". For malformed inputs with
// fewer than three fields it falls back to the last field.
func lastPart(s, sep string) string {
	parts := strings.Split(s, sep)
	if len(parts) >= 3 {
		return parts[2]
	}
	if len(parts) == 0 {
		return s
	}
	return parts[len(parts)-1]
}

// suggestSELinuxFix attempts to find the best remediation for an AVC denial.
// Priority order (per SELinux admin best practice):
//  1. Boolean fix (getsebool) — least invasive, covers most container cases
//  2. semanage fcontext — persistent file context fix
//  3. semanage port — port labeling fix
//  4. audit2allow guidance — last resort
func suggestSELinuxFix(ctx context.Context, stype, ttype, tclass string, perms []string) (boolName, fixCmd string) {
	// Well-known boolean mappings for common denial patterns
	// (stype_prefix, ttype_prefix, tclass) → boolean name
	type booleanRule struct{ sPrefix, tPrefix, tclass, boolName string }
	knownBooleans := []booleanRule{
		// Container/Podman patterns
		{secTypeContainer, "", "bpf", "container_use_devices"},
		{secTypeContainer, "", secTypeFile, "container_file_lock"},
		{secTypeContainer, secSvcHTTPD, "", "httpd_can_network_connect"},
		{secSvcHTTPD, "db", "", "httpd_can_network_connect_db"},
		{secSvcHTTPD, "", secTypePort, "httpd_can_network_relay"},
		// SSH / network patterns
		{"sshd", "", secTypePort, "selinuxuser_tcp_server"},
		{secSvcSSH, "", secTypePort, "ssh_use_tcpd"},
		// NFS / file patterns
		{"nfsd", "", secTypeFile, "nfs_export_all_rw"},
		{"smbd", "", secTypeFile, "samba_export_all_rw"},
		// Cron patterns
		{"crond", "", secTypeFile, "cron_can_relabel"},
	}

	stypeLower := strings.ToLower(stype)
	ttypeLower := strings.ToLower(ttype)
	tclassLower := strings.ToLower(tclass)

	for _, rule := range knownBooleans {
		sMatch := rule.sPrefix == "" || strings.Contains(stypeLower, rule.sPrefix)
		tMatch := rule.tPrefix == "" || strings.Contains(ttypeLower, rule.tPrefix)
		cMatch := rule.tclass == "" || strings.Contains(tclassLower, rule.tclass)
		if sMatch && tMatch && cMatch {
			// Verify the boolean actually exists on this system
			if boolExists(ctx, rule.boolName) {
				return rule.boolName,
					fmt.Sprintf("setsebool -P %s on", rule.boolName)
			}
		}
	}

	// Port labeling — semanage port
	if tclass == "tcp_socket" || tclass == "udp_socket" {
		fixCmd = fmt.Sprintf("semanage port -a -t %s_port_t -p tcp <PORT>", stype)
		return "", fixCmd
	}

	// File context — semanage fcontext
	if tclass == secTypeFile || tclass == "dir" {
		for _, perm := range perms {
			if perm == "read" || perm == "write" || perm == "open" || perm == "create" {
				fixCmd = fmt.Sprintf("semanage fcontext -a -t %s_t '/path/to/file'  && restorecon -v /path/to/file", ttype)
				return "", fixCmd
			}
		}
	}

	// Fallback: audit2allow
	fixCmd = fmt.Sprintf(
		"ausearch -m avc -ts recent | audit2allow -M my_%s && semodule -i my_%s.pp",
		stype, stype)
	return "", fixCmd
}

// boolExists returns true if an SELinux boolean with the given name is available.
func boolExists(ctx context.Context, name string) bool {
	out, err := runCmd(ctx, "getsebool", name)
	return err == nil && strings.Contains(out, name)
}
