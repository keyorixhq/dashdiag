//go:build linux

package collectors

import (
	"bufio"
	"context"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/keyorixhq/dashdiag/internal/models"
	"github.com/keyorixhq/dashdiag/internal/platform"
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

	parseSSHConfig(info)
	parseFailedLogins(info)
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
func parseSSHConfig(info *models.SecurityInfo) {
	// Default safe values (OpenSSH modern defaults)
	info.SSHPubkeyAuth = true   // on by default in modern OpenSSH
	info.SSHStrictModes = true  // on by default
	info.SSHIgnoreRhosts = true // on by default in modern OpenSSH

	// Try sshd -T first — gives the fully merged effective configuration.
	// On RHEL 10 this requires root; non-root exits 0 but prints "Permission denied".
	if out, err := exec.Command("sshd", "-T").Output(); err == nil {
		outStr := string(out)
		if !strings.Contains(outStr, "Permission denied") && len(strings.TrimSpace(outStr)) > 0 {
			parseSSHFileContent(outStr, info)
			info.SSHAuditSource = "sshd -T"
			return
		}
	}

	// Fall back to file parsing (works without root, may miss drop-ins on some distros)
	parseSSHFile("/etc/ssh/sshd_config", info)
	for _, pattern := range []string{
		"/etc/ssh/sshd_config.d/*.conf",
		"/etc/ssh/sshd_config.d/*.cfg",
	} {
		if files, err := filepath.Glob(pattern); err == nil {
			for _, f := range files {
				parseSSHFile(f, info)
			}
		}
	}
}

// parseSSHFile reads a single sshd_config file or drop-in and populates SecurityInfo.
func parseSSHFile(path string, info *models.SecurityInfo) {
	f, err := os.Open(path) // #nosec G304 -- only reads well-known config paths
	if err != nil {
		return
	}
	defer f.Close() //nolint:errcheck

	content := new(strings.Builder)
	buf := make([]byte, 64*1024)
	for {
		n, readErr := f.Read(buf)
		if n > 0 {
			content.Write(buf[:n])
		}
		if readErr != nil {
			break
		}
	}
	parseSSHFileContent(content.String(), info)
}

// parseSSHFileContent parses sshd_config content from a string — used by tests.
func parseSSHFileContent(content string, info *models.SecurityInfo) {
	scanner := bufio.NewScanner(strings.NewReader(content))
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
			// "without-password" is an alias for "prohibit-password" in older OpenSSH.
			// Both mean: key-based root login allowed, but not password-based.
			// This is a weaker restriction than "no" but not as bad as "yes".
			info.SSHPermitRoot = val != "no" && val != "prohibit-password" && val != "without-password"
		case "passwordauthentication":
			info.SSHPasswordAuth = val == "yes"
		case "pubkeyauthentication":
			info.SSHPubkeyAuth = val == "yes"
		case "port":
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
			info.SSHX11Forwarding = val == "yes"
		case "allowagentforwarding":
			info.SSHAgentForwarding = val == "yes"
		case "permitemptypasswords":
			info.SSHPermitEmptyPwd = val == "yes"
		case "strictmodes":
			// StrictModes defaults to yes — only flag when explicitly disabled
			info.SSHStrictModes = val != "no"
		case "clientaliveinterval":
			if n, err := strconv.Atoi(val); err == nil {
				info.SSHClientAliveInterval = n
			}
		case "ignorerhosts":
			info.SSHIgnoreRhosts = val != "no"
		case "hostbasedauthentication":
			info.SSHHostbasedAuth = val == "yes"
		case "permituserenvironment":
			info.SSHPermitUserEnv = val == "yes"
		case "allowtcpforwarding":
			info.SSHTCPForwarding = val == "yes"
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
	for _, c := range s {
		switch {
		case c >= '0' && c <= '9':
			num += string(c)
		case c == 's':
			if n, err := strconv.Atoi(num); err == nil {
				total += n
			}
			num = ""
		case c == 'm':
			if n, err := strconv.Atoi(num); err == nil {
				total += n * 60
			}
			num = ""
		case c == 'h':
			if n, err := strconv.Atoi(num); err == nil {
				total += n * 3600
			}
			num = ""
		}
	}
	// bare number without unit = seconds
	if num != "" {
		if n, err := strconv.Atoi(num); err == nil {
			total += n
		}
	}
	return total
}

// parseFailedLogins reads /var/log/secure (RHEL) or /var/log/auth.log (Debian).
// Falls back to journalctl on systems using journald-only auth logging (Debian 13+).
// Counts failed SSH login attempts in the last hour.
func parseFailedLogins(info *models.SecurityInfo) {
	paths := []string{"/var/log/secure", "/var/log/auth.log"}
	var logPath string
	for _, p := range paths {
		if _, err := os.Stat(p); err == nil {
			logPath = p
			break
		}
	}
	if logPath == "" {
		// Neither file exists — Debian 13+ with journald-only auth logging.
		// Fall back to journalctl which reads from the binary journal directly.
		parseFailedLoginsFromJournal(info)
		return
	}

	f, err := os.Open(logPath) // #nosec G304 -- hardcoded known paths
	if err != nil {
		return // requires root
	}
	defer f.Close() //nolint:errcheck

	ipCount := make(map[string]int)
	cutoff := time.Now().Add(-1 * time.Hour)

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := scanner.Text()
		if !strings.Contains(line, "Failed password") && !strings.Contains(line, "Invalid user") {
			continue
		}
		// Parse timestamp — format: "May 11 15:04:05"
		if len(line) < 15 {
			continue
		}
		ts, err := parseLogTimestamp(line[:15])
		if err != nil || ts.Before(cutoff) {
			continue
		}
		info.FailedLogins++
		// Extract source IP: "from 1.2.3.4 port"
		if idx := strings.Index(line, " from "); idx >= 0 {
			rest := line[idx+6:]
			ipEnd := strings.IndexByte(rest, ' ')
			if ipEnd > 0 {
				ip := rest[:ipEnd]
				if net.ParseIP(ip) != nil {
					ipCount[ip]++
				}
			}
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

// parseFailedLoginsFromJournal reads failed SSH logins from journald.
// Used on systems where /var/log/secure and /var/log/auth.log do not exist
// (Debian 13+ with journald-only auth logging).
// Handles two sshd log formats:
//   - Legacy (OpenSSH ≤8): "Failed password for [invalid user] X from IP port P ssh2"
//   - Modern (OpenSSH 9+): "drop connection #N from [IP]:P on [IP]:P penalty: failed authentication"
func parseFailedLoginsFromJournal(info *models.SecurityInfo) {
	out, err := exec.Command("journalctl", "_COMM=sshd", "--since=1 hour ago", "--no-pager", "-q").Output()
	if err != nil {
		return
	}

	ipCount := make(map[string]int)
	for _, line := range strings.Split(string(out), "\n") {
		var ip string

		switch {
		// Legacy format: "Failed password" or "Invalid user"
		case strings.Contains(line, "Failed password") || strings.Contains(line, "Invalid user"):
			if idx := strings.Index(line, " from "); idx >= 0 {
				rest := line[idx+6:]
				ipEnd := strings.IndexByte(rest, ' ')
				if ipEnd > 0 {
					ip = rest[:ipEnd]
				}
			}

		// Modern format (OpenSSH 9+): "drop connection #N from [IP]:port ... penalty: failed authentication"
		case strings.Contains(line, "penalty: failed authentication"):
			// Extract IP from: "from [192.168.1.1]:12345"
			if idx := strings.Index(line, " from ["); idx >= 0 {
				rest := line[idx+7:]
				ipEnd := strings.IndexByte(rest, ']')
				if ipEnd > 0 {
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

	for ip, count := range ipCount {
		if count >= 3 {
			info.FailedLoginIPs = append(info.FailedLoginIPs,
				fmt.Sprintf("%s (%d attempts)", ip, count))
		}
	}
}

// parseLogTimestamp parses syslog-style timestamps like "May 11 15:04:05".
// Uses current year since syslog doesn't include it.
func parseLogTimestamp(s string) (time.Time, error) {
	year := time.Now().Year()
	return time.Parse("2006 Jan  2 15:04:05", fmt.Sprintf("%d %s", year, s))
}

// parseListeningPorts reads /proc/net/tcp and /proc/net/tcp6 directly.
// Only reports ports listening on 0.0.0.0 (all interfaces).
func parseListeningPorts(info *models.SecurityInfo) {
	for _, path := range []string{"/proc/net/tcp", "/proc/net/tcp6"} {
		parseProcNetTCP(path, info)
	}
}

func parseProcNetTCP(path string, info *models.SecurityInfo) {
	f, err := os.Open(path) // #nosec G304 -- hardcoded /proc path
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
		procName := inodeProc[inode]
		if !hasRoot && procName == "" {
			procName = "" // will show note in drilldown
		}

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
				Protocol: "tcp",
				Process:  procName,
				Expected: isExpectedPort(port),
			})
		}
	}
	if !hasRoot || os.Getuid() != 0 {
		info.PortsNeedRoot = true
	}
}

// buildInodeProcMap builds a map of socket inode → process name.
// Returns the map and a bool indicating whether root-level fd access was available.
func buildInodeProcMap() (map[string]string, bool) {
	result := make(map[string]string)
	dirs, err := filepath.Glob("/proc/[0-9]*/fd")
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
		comm, err := os.ReadFile("/proc/" + pid + "/comm") // #nosec G304
		if err != nil {
			continue
		}
		procName := strings.TrimSpace(string(comm))
		fds, err := os.ReadDir(fdDir)
		if err != nil {
			continue
		}
		hasRoot = true // we could read at least one process's fds
		for _, fd := range fds {
			link, err := os.Readlink(fdDir + "/" + fd.Name())
			if err != nil {
				continue
			}
			if strings.HasPrefix(link, "socket:[") && strings.HasSuffix(link, "]") {
				inode := link[8 : len(link)-1]
				if _, exists := result[inode]; !exists {
					result[inode] = procName
				}
			}
		}
	}
	return result, hasRoot
}

// isExpectedPort returns true for universally standard ports that are
// almost never a security concern. Kubernetes and other services are
// intentionally NOT listed here — users should see them and decide.
// TODO(backlog): let users configure expected ports via dsd config.
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

// parseSudoers scans /etc/sudoers and /etc/sudoers.d/ for NOPASSWD entries.
func parseSudoers(info *models.SecurityInfo) {
	paths := []string{"/etc/sudoers"}
	if entries, err := filepath.Glob("/etc/sudoers.d/*"); err == nil {
		paths = append(paths, entries...)
	}
	for _, p := range paths {
		parseSudoersFile(p, info)
	}
}

func parseSudoersFile(path string, info *models.SecurityInfo) {
	f, err := os.Open(filepath.Clean(path))
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
		// Extract the user/group — first field before whitespace
		fields := strings.Fields(line)
		if len(fields) > 0 {
			user := fields[0]
			// Skip ALL — these are system-wide NOPASSWD for specific commands
			// (e.g. mintdrivers, mintupdate on Linux Mint) not full privilege escalation
			if user == "ALL" {
				continue
			}
			info.SudoNopasswd = append(info.SudoNopasswd, user)
		}
	}
}

// parseSELinuxDenials reads the audit log directly for recent AVC denials.
func parseSELinuxDenials(ctx context.Context, info *models.SecurityInfo) {
	// Check if SELinux is active
	mode, err := os.ReadFile("/sys/fs/selinux/enforce") // #nosec G304
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
	if os.Getuid() == 0 && n > 0 {
		info.SELinuxAVCGroups = parseAVCGroups(ctx, 1*time.Hour)
	}

	_ = ctx // reserved for future timeout use
}

// suidScanPaths are filesystem roots to scan for unexpected SUID binaries.
// Deliberately excludes /proc and /sys virtual filesystems.
var suidScanPaths = []string{"/usr/local", "/opt", "/home", "/tmp", "/var/tmp"}

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
	for _, root := range suidScanPaths {
		_ = filepath.Walk(root, func(path string, fi os.FileInfo, err error) error {
			if err != nil || fi.IsDir() {
				return nil
			}
			if stat, ok := fi.Sys().(*syscall.Stat_t); ok {
				if stat.Mode&syscall.S_ISUID != 0 && !knownSUIDBinaries[path] {
					info.SUIDBinaries = append(info.SUIDBinaries, path)
				}
			}
			return nil
		})
	}
}

// parseSELinuxExtras adds booleans, AppArmor groups, autorelabel, and PAM lockout.
func parseSELinuxExtras(ctx context.Context, info *models.SecurityInfo) {
	// /.autorelabel — full filesystem relabel queued
	if _, err := os.Stat("/.autorelabel"); err == nil {
		info.SELinuxAutoRelabel = true
	}

	// Relevant off booleans for denied scontexts
	if len(info.SELinuxAVCGroups) > 0 {
		info.SELinuxBooleans = collectRelevantBooleans(ctx, info.SELinuxAVCGroups)
	}

	// AppArmor denial grouping (Debian/Ubuntu/SUSE)
	if info.AppArmorMode != "" && info.AppArmorMode != "disabled" {
		info.AppArmorGroups = collectAppArmorDenials(ctx)
		info.AppArmorDenials = 0
		for _, g := range info.AppArmorGroups {
			info.AppArmorDenials += g.Count
		}
	}

	// PAM locked accounts via faillock
	info.PAMLockedAccounts = collectPAMLockedAccounts(ctx)
}

// collectRelevantBooleans runs getsebool -a and filters to booleans related to
// the denied scontexts that are currently OFF.
func collectRelevantBooleans(ctx context.Context, groups []models.SELinuxAVCGroup) []models.SELinuxBoolean {
	out, err := runCmdTimeout(5*time.Second, "getsebool", "-a")
	if err != nil {
		return nil
	}

	// Build set of scontext prefixes to search for (e.g. "httpd" from "httpd_t")
	keywords := make(map[string]bool)
	for _, g := range groups {
		// "httpd_t" → "httpd"; "container_runtime_t" → "container"
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
func collectAppArmorDenials(ctx context.Context) []models.AppArmorDenial {
	jCtx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	out, err := runCmd(jCtx, "journalctl", "-t", "kernel", "-g", `apparmor="DENIED"`,
		"--no-pager", "--since", "24 hours ago", "-o", "short")
	if err != nil || strings.TrimSpace(out) == "" {
		return nil
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
	return groups
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
	data, err := os.ReadFile("/etc/passwd") // #nosec G304
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
		entries, err := os.ReadDir(dir)
		if err != nil {
			continue
		}
		for _, e := range entries {
			if e.IsDir() {
				continue
			}
			path := filepath.Join(dir, e.Name())
			data, err := os.ReadFile(filepath.Clean(path)) // #nosec G304 -- hardcoded dirs
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
	out, err := runCmd(ctx, "firewall-cmd", "--state")
	if err != nil || strings.TrimSpace(out) != "running" {
		return false
	}
	info.FirewallActive = true
	info.FirewallType = "firewalld"

	// Active zone
	if zoneOut, err := runCmd(ctx, "firewall-cmd", "--get-default-zone"); err == nil {
		info.FirewallZone = strings.TrimSpace(zoneOut)
	}

	// Allowed services in active zone
	rulesRead := false
	if svcOut, err := runCmd(ctx, "firewall-cmd", "--list-services"); err == nil {
		rulesRead = true
		for _, svc := range strings.Fields(svcOut) {
			info.FirewallServices = append(info.FirewallServices, svc)
		}
	}

	// SSH allowed?
	info.SSHAllowed = false
	for _, svc := range info.FirewallServices {
		if svc == "ssh" {
			info.SSHAllowed = true
			break
		}
	}
	// Also check explicit port 22
	if !info.SSHAllowed {
		if portsOut, err := runCmd(ctx, "firewall-cmd", "--list-ports"); err == nil {
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
	out, err := runCmd(ctx, "ufw", "status")
	if err != nil {
		return false
	}
	lower := strings.ToLower(out)
	// "Status: inactive" contains "active" as substring — check for "status: active" specifically
	if !strings.Contains(lower, "status: active") {
		return false
	}
	info.FirewallActive = true
	info.FirewallType = "ufw"
	// ufw status shows "22/tcp ALLOW" or "OpenSSH ALLOW"
	info.SSHAllowed = strings.Contains(lower, "22") && strings.Contains(lower, "allow") ||
		strings.Contains(lower, "openssh") && strings.Contains(lower, "allow")
	return true
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
	if _, err := exec.LookPath("nft"); err == nil {
		if out, err := runCmd(ctx, "nft", "list", "ruleset"); err == nil {
			fw := &models.FirewallInfo{}
			parseNFTRuleset(out, fw)
			if fw.TotalRules > 0 {
				info.FirewallActive = true
				info.FirewallType = "nftables"
				info.SSHAllowed = sshAllowedNFT(out, sshPort(info))
				return true
			}
		}
	}
	// Fallback: nft binary missing — infer from on-disk config. We can't read
	// the ruleset here, so leave SSH reachability conservatively "allowed".
	entries, _ := filepath.Glob("/etc/nftables.conf")
	if len(entries) == 0 {
		entries, _ = filepath.Glob("/etc/nftables.d/*.nft")
	}
	if len(entries) > 0 {
		info.FirewallActive = true
		info.FirewallType = "nftables"
		info.SSHAllowed = true // conservative — config present but rules unread
		return true
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
	if _, err := exec.LookPath("iptables"); err != nil {
		return false
	}
	out, err := runCmd(ctx, "iptables", "-L", "-n", "--line-numbers")
	if err != nil {
		return false
	}
	fw := &models.FirewallInfo{}
	parseIPTList(out, fw)
	if fw.TotalRules > 0 {
		info.FirewallActive = true
		info.FirewallType = "iptables"
		info.SSHAllowed = sshAllowedIPT(out, sshPort(info))
		return true
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
// firewalld/ufw service checks, and biases toward "allowed": it reports blocked
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
		if !portWord.MatchString(low) && !strings.Contains(low, "ssh") {
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

// decideSSHAllowed applies the shared decision, biased toward "allowed": an
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
	data, err := os.ReadFile("/proc/sys/crypto/fips_enabled") // #nosec G304
	if err != nil {
		return
	}
	info.FIPSEnabled = strings.TrimSpace(string(data)) == "1"
}

// parseCryptoPolicy reads the active system-wide cryptographic policy.
// RHEL/Rocky uses /etc/crypto-policies/config (DEFAULT, LEGACY, FUTURE, FIPS).
func parseCryptoPolicy(ctx context.Context, info *models.SecurityInfo) {
	// Prefer reading the config file directly — no subprocess needed
	if data, err := os.ReadFile("/etc/crypto-policies/config"); err == nil { // #nosec G304
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
	data, err := os.ReadFile("/sys/class/usb_device") // #nosec G304
	_ = data
	// usbguard detection: check if the service unit exists and is active
	if _, err2 := os.Stat("/usr/sbin/usbguard"); err2 == nil {
		// Binary present — check if service is active via systemd cgroup
		if _, err3 := os.Stat("/sys/fs/cgroup/system.slice/usbguard.service"); err3 == nil {
			info.USBGuardActive = true
			return
		}
	}
	_ = err
	// Fallback: check pid file or socket
	if _, err4 := os.Stat("/run/usbguard/usbguard-daemon.pid"); err4 == nil {
		info.USBGuardActive = true
	}
}

// parseAIDE checks if AIDE is installed and when the database was last updated.
func parseAIDE(info *models.SecurityInfo) {
	// Check binary
	aidePaths := []string{"/usr/sbin/aide", "/usr/bin/aide"}
	for _, p := range aidePaths {
		if _, err := os.Stat(p); err == nil {
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
		if fi, err := os.Stat(p); err == nil {
			info.AIDEDBExists = true
			days := int(time.Since(fi.ModTime()).Hours() / 24)
			info.AIDELastRunDays = days
			return
		}
	}
	info.AIDELastRunDays = -1 // installed but never run
}

// parseAuditRules counts active auditd rules via auditctl.
// Returns -1 when auditctl is unavailable or auditd not running.
func parseAuditRules(ctx context.Context, info *models.SecurityInfo) {
	out, err := runCmd(ctx, "auditctl", "-l")
	if err != nil {
		info.AuditRules = -1
		return
	}
	// "No rules" means auditd running but empty ruleset
	if strings.Contains(out, "No rules") || strings.TrimSpace(out) == "" {
		info.AuditRules = 0
		return
	}
	count := 0
	for _, line := range strings.Split(out, "\n") {
		line = strings.TrimSpace(line)
		if line != "" && !strings.HasPrefix(line, "#") {
			count++
		}
	}
	info.AuditRules = count
}

// parseSupportconfig detects SUSE's supportconfig diagnostic tool.
// supportutils package provides /usr/sbin/supportconfig.
// Archives are saved to /var/log/ as nts_HOST_DATE.tbz or scc_HOST_DATE.txz.
func parseSupportconfig(info *models.SecurityInfo) {
	// Check binary exists
	paths := []string{"/usr/sbin/supportconfig", "/sbin/supportconfig"}
	for _, p := range paths {
		if _, err := os.Stat(p); err == nil {
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

	var newest os.FileInfo
	var newestPath string

	// Also check for directory-based output (SLES 16 default)
	if entries, err := os.ReadDir("/var/log"); err == nil {
		for _, e := range entries {
			if e.IsDir() && (strings.HasPrefix(e.Name(), "scc_") || strings.HasPrefix(e.Name(), "nts_")) {
				p := "/var/log/" + e.Name()
				fi, err := e.Info()
				if err == nil && (newest == nil || fi.ModTime().After(newest.ModTime())) {
					newest = fi
					newestPath = p
				}
			}
		}
	}

	for _, pattern := range patterns {
		matches, err := filepath.Glob(pattern)
		if err != nil {
			continue
		}
		for _, match := range matches {
			// Skip .md5 checksum files
			if strings.HasSuffix(match, ".md5") {
				continue
			}
			fi, err := os.Stat(match)
			if err != nil {
				continue
			}
			if newest == nil || fi.ModTime().After(newest.ModTime()) {
				newest = fi
				newestPath = match
			}
		}
	}

	if newest == nil {
		info.SupportconfigLastRunDays = -1 // never run
		return
	}

	info.SupportconfigArchive = newestPath
	info.SupportconfigLastRunDays = int(time.Since(newest.ModTime()).Hours() / 24)
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
// [{"identifier":"SLES","status":"Registered","subscription_status":"ACTIVE",
//
//	"expires_at":"2026-07-13 00:00:00 UTC","type":"evaluation",...}]
func parseSUSEConnect(ctx context.Context, info *models.SecurityInfo) {
	CollectSUSEConnect(ctx, info)
}

// CollectSUSEConnect populates SUSEConnect subscription fields into info.
// Exported so SUSEConnectCollector can call it directly without duplicating logic.
func CollectSUSEConnect(ctx context.Context, info *models.SecurityInfo) {
	if _, err := exec.LookPath("SUSEConnect"); err != nil {
		return
	}
	out, err := runCmd(ctx, "SUSEConnect", "--status")
	if err != nil || strings.TrimSpace(out) == "" {
		return
	}

	lower := strings.ToLower(out)
	if !strings.Contains(lower, "registered") && !strings.Contains(lower, "identifier") {
		return
	}

	info.SUSEConnectRegistered = strings.Contains(lower, "\"registered\"") ||
		strings.Contains(lower, "registered")

	// Extract subscription_status
	if idx := strings.Index(lower, "subscription_status"); idx >= 0 {
		rest := out[idx:]
		if start := strings.Index(rest, `"`); start >= 0 {
			rest = rest[start+1:]
			if colon := strings.Index(rest, `"`); colon >= 0 {
				rest = rest[colon+1:]
				if end := strings.Index(rest, `"`); end >= 0 {
					info.SUSEConnectStatus = rest[:end]
				}
			}
		}
	}

	// Extract expires_at and compute days remaining
	if idx := strings.Index(out, "expires_at"); idx >= 0 {
		rest := out[idx:]
		// Format: "expires_at":"2026-07-13 00:00:00 UTC"
		if start := strings.Index(rest, `":"`); start >= 0 {
			rest = rest[start+3:]
			if end := strings.Index(rest, `"`); end >= 0 {
				expiryStr := strings.TrimSpace(rest[:end])
				// Parse "2026-07-13 00:00:00 UTC"
				t, err := time.Parse("2006-01-02 15:04:05 MST", expiryStr)
				if err == nil {
					days := int(time.Until(t).Hours() / 24)
					if days < 0 {
						days = 0 // expired
					}
					info.SUSEConnectExpiresDays = days
				} else {
					info.SUSEConnectExpiresDays = -1
				}
			}
		}
	}
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
	data, err := os.ReadFile("/etc/os-release") // #nosec G304
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
	shadow, err := os.ReadFile("/etc/shadow") // #nosec G304 -- hardcoded system file, root only
	if err != nil {
		return // requires root — silent skip
	}

	// Build UID lookup from /etc/passwd to filter human accounts
	humanAccounts := map[string]bool{}
	if passwd, err := os.ReadFile("/etc/passwd"); err == nil { // #nosec G304
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
		fi, err := os.Stat(dir)
		if err != nil {
			continue
		}
		mode := fi.Mode()
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
func parseAVCGroups(ctx context.Context, window time.Duration) []models.SELinuxAVCGroup {
	f, err := os.Open("/var/log/audit/audit.log") // #nosec G304 -- hardcoded audit log path
	if err != nil {
		return nil
	}
	defer f.Close() //nolint:errcheck

	type groupKey struct{ stype, ttype, tclass string }
	type groupData struct {
		perms map[string]bool
		count int
	}
	groups := map[groupKey]*groupData{}
	cutoff := time.Now().Add(-window)

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := scanner.Text()
		if !strings.Contains(line, "type=AVC") {
			continue
		}
		// Timestamp check
		if idx := strings.Index(line, "msg=audit("); idx >= 0 {
			rest := line[idx+10:]
			if dot := strings.IndexByte(rest, '.'); dot > 0 {
				if sec, err := strconv.ParseInt(rest[:dot], 10, 64); err == nil {
					if !time.Unix(sec, 0).After(cutoff) {
						continue
					}
				}
			}
		}

		stype := avcField(line, "scontext=")
		ttype := avcField(line, "tcontext=")
		tclass := avcField(line, "tclass=")
		perms := avcPerms(line)

		if stype == "" || ttype == "" || tclass == "" {
			continue
		}
		// Keep only the type component (last part of user:role:type:level)
		stype = lastPart(stype, ":")
		ttype = lastPart(ttype, ":")

		key := groupKey{stype, ttype, tclass}
		if _, ok := groups[key]; !ok {
			groups[key] = &groupData{perms: map[string]bool{}}
		}
		for _, p := range perms {
			groups[key].perms[p] = true
		}
		groups[key].count++
	}

	if len(groups) == 0 {
		return nil
	}

	// Build result slice, sorted by count descending
	var result []models.SELinuxAVCGroup
	for key, data := range groups {
		perms := make([]string, 0, len(data.perms))
		for p := range data.perms {
			perms = append(perms, p)
		}
		g := models.SELinuxAVCGroup{
			Scontext: key.stype,
			Tcontext: key.ttype,
			Tclass:   key.tclass,
			Perms:    perms,
			Count:    data.count,
		}
		// Try to find a boolean fix or semanage command
		g.BooleanFix, g.FixCmd = suggestSELinuxFix(ctx, key.stype, key.ttype, key.tclass, perms)
		result = append(result, g)
	}
	// Sort by count descending (most frequent first)
	for i := 1; i < len(result); i++ {
		for j := i; j > 0 && result[j].Count > result[j-1].Count; j-- {
			result[j], result[j-1] = result[j-1], result[j]
		}
	}
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
		{"container", "", "bpf", "container_use_devices"},
		{"container", "", "file", "container_file_lock"},
		{"container", "httpd", "", "httpd_can_network_connect"},
		{"httpd", "db", "", "httpd_can_network_connect_db"},
		{"httpd", "", "port", "httpd_can_network_relay"},
		// SSH / network patterns
		{"sshd", "", "port", "selinuxuser_tcp_server"},
		{"ssh", "", "port", "ssh_use_tcpd"},
		// NFS / file patterns
		{"nfsd", "", "file", "nfs_export_all_rw"},
		{"smbd", "", "file", "samba_export_all_rw"},
		// Cron patterns
		{"crond", "", "file", "cron_can_relabel"},
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
	if tclass == "file" || tclass == "dir" {
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
