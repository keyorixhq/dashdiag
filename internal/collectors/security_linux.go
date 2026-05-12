//go:build linux

package collectors

import (
	"bufio"
	"context"
	"fmt"
	"net"
	"os"
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
		22:   true, // SSH
		80:   true, // HTTP
		443:  true, // HTTPS
		9090: true, // Cockpit (RHEL web console)
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

	// Delegate to the shared audit log reader in kernel_security.go.
	// Returns (0, false) when /var/log/audit/audit.log is unreadable (non-root).
	if n, ok := countAVCsFromAuditLog(1 * time.Hour); ok {
		info.SELinuxDenials = n
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
