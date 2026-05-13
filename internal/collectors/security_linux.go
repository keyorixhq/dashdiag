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
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/keyorixhq/dashdiag/internal/models"
)

// SecurityCollector reads system security posture directly from kernel and
// config files. No external tools except SUID detection (find).
type SecurityCollector struct{}

func NewSecurityCollector() *SecurityCollector { return &SecurityCollector{} }

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

	return info, nil
}

// parseSSHConfig reads /etc/ssh/sshd_config directly.
func parseSSHConfig(info *models.SecurityInfo) {
	f, err := os.Open("/etc/ssh/sshd_config") // #nosec G304 -- hardcoded path
	if err != nil {
		return
	}
	defer f.Close() //nolint:errcheck

	scanner := bufio.NewScanner(f)
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
			info.SSHPermitRoot = val != "no" && val != "prohibit-password"
		case "passwordauthentication":
			info.SSHPasswordAuth = val == "yes"
		}
	}
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
			info.SudoNopasswd = append(info.SudoNopasswd, fields[0])
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

// parseUID0Users scans /etc/passwd for non-root accounts with UID 0.
// Only root should have UID 0. Any other UID-0 account is a critical finding.
func parseUID0Users(info *models.SecurityInfo) {
	data, err := os.ReadFile("/etc/passwd") // #nosec G304 -- hardcoded system file
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
	if detectNFTables(info) {
		return
	}
	// iptables — legacy, common on older systems
	if detectIPTables(info) {
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
	if svcOut, err := runCmd(ctx, "firewall-cmd", "--list-services"); err == nil {
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
			if strings.Contains(portsOut, "22/tcp") {
				info.SSHAllowed = true
			}
		}
	}
	return true
}

func detectUFW(ctx context.Context, info *models.SecurityInfo) bool {
	out, err := runCmd(ctx, "ufw", "status")
	if err != nil {
		return false
	}
	lower := strings.ToLower(out)
	if !strings.Contains(lower, "active") {
		return false
	}
	info.FirewallActive = true
	info.FirewallType = "ufw"
	// ufw status shows "22/tcp ALLOW" or "OpenSSH ALLOW"
	info.SSHAllowed = strings.Contains(lower, "22") && strings.Contains(lower, "allow") ||
		strings.Contains(lower, "openssh") && strings.Contains(lower, "allow")
	return true
}

func detectNFTables(info *models.SecurityInfo) bool {
	data, err := os.ReadFile("/proc/net/nf_conntrack_stat") // #nosec G304
	if err != nil {
		// Try listing nft tables instead
		if _, err2 := os.Stat("/proc/sys/net/netfilter"); err2 != nil {
			return false
		}
	}
	_ = data
	// Check if nftables has any rules
	entries, _ := filepath.Glob("/etc/nftables.conf")
	if len(entries) == 0 {
		entries, _ = filepath.Glob("/etc/nftables.d/*.nft")
	}
	if len(entries) > 0 {
		info.FirewallActive = true
		info.FirewallType = "nftables"
		info.SSHAllowed = true // conservative — assume SSH ok unless we parse rules
		return true
	}
	return false
}

func detectIPTables(info *models.SecurityInfo) bool {
	// Check if iptables has non-trivial rules (INPUT chain has entries)
	data, err := os.ReadFile("/proc/net/ip_tables_names") // #nosec G304
	if err != nil {
		return false
	}
	if strings.Contains(string(data), "filter") {
		info.FirewallActive = true
		info.FirewallType = "iptables"
		info.SSHAllowed = true // conservative default
		return true
	}
	return false
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
