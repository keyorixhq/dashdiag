//go:build linux

package collectors

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/keyorixhq/dashdiag/internal/models"
)

// ProcCollector reads detailed diagnostics for a single process.
// Zero-impact: reads /proc filesystem only — no ptrace, no strace.
// Linux only; macOS stub returns empty info.
type ProcCollector struct {
	PID int // 0 = top-list mode
}

func NewProcCollector(pid int) *ProcCollector { return &ProcCollector{PID: pid} }

func (c *ProcCollector) Name() string           { return "Proc" }
func (c *ProcCollector) Timeout() time.Duration { return 5 * time.Second }

func (c *ProcCollector) Collect(ctx context.Context) (interface{}, error) {
	if c.PID == 0 {
		// Top-list mode — reuse existing top-process data
		info := &models.ProcInfo{}
		topProcs, _ := topMemoryProcs(15)
		info.TopProcs = topProcs
		return info, nil
	}
	return collectProcPID(c.PID)
}

// collectProcPID reads all /proc/<pid>/ files for a given PID.
func collectProcPID(pid int) (*models.ProcInfo, error) {
	base := fmt.Sprintf("/proc/%d", pid)

	// Verify PID exists
	if _, err := os.Stat(base); err != nil {
		return nil, fmt.Errorf("PID %d not found", pid)
	}

	info := &models.ProcInfo{PID: pid}

	// Status file — name, state, PPID, threads, FDSize, VmRSS, VmSwap
	parseProcStatus(base, info)

	// Cmdline
	if data, err := os.ReadFile(base + "/cmdline"); err == nil { // #nosec G304
		info.Cmdline = strings.ReplaceAll(
			strings.TrimRight(string(data), "\x00"), "\x00", " ")
		if len(info.Cmdline) > 200 {
			info.Cmdline = info.Cmdline[:200] + "…"
		}
	}

	// wchan — kernel function the process is blocked on
	if data, err := os.ReadFile(base + "/wchan"); err == nil { // #nosec G304
		info.WChan = strings.TrimSpace(string(data))
	}
	info.DState = info.State == "D"

	// Uptime via /proc/PID/stat field 22 (starttime in jiffies)
	info.UptimeSec = procUptimeSec(base)

	// CPU time from /proc/PID/stat fields 14+15 (utime+stime in jiffies)
	info.CPUSec = procCPUSec(base)

	// FD count and limit
	info.FDCount, info.FDLimit = procFDInfo(base)
	if info.FDLimit > 0 {
		info.FDPressure = float64(info.FDCount)/float64(info.FDLimit) > 0.80
	}

	// Memory map from smaps_rollup (kernel 4.14+) or smaps fallback
	info.MemMap = procMemMap(base)

	// Owner user
	info.User = procUser(base)

	// Parent name
	if info.PPID > 0 {
		if data, err := os.ReadFile(
			fmt.Sprintf("/proc/%d/comm", info.PPID)); err == nil { // #nosec G304
			info.ParentName = strings.TrimSpace(string(data))
		}
	}

	// Cgroup (last path component for readability)
	if data, err := os.ReadFile(base + "/cgroup"); err == nil { // #nosec G304
		for _, line := range strings.Split(string(data), "\n") {
			line = strings.TrimSpace(line)
			if line == "" {
				continue
			}
			// Format: "0::/system.slice/docker.service" — take everything after last ":"
			parts := strings.SplitN(line, ":", 3)
			if len(parts) == 3 && parts[2] != "/" {
				info.CgroupName = filepath.Base(parts[2])
			}
			break
		}
	}

	// Open files: read /proc/PID/fd symlinks
	inodes := collectOpenFiles(base, info)

	// Network connections for this process's socket inodes
	info.Connections = procNetConns(inodes)

	return info, nil
}

// parseProcStatus reads /proc/PID/status for key fields.
func parseProcStatus(base string, info *models.ProcInfo) {
	data, err := os.ReadFile(base + "/status") // #nosec G304
	if err != nil {
		return
	}
	for _, line := range strings.Split(string(data), "\n") {
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		switch strings.TrimSuffix(fields[0], ":") {
		case "Name":
			info.Name = fields[1]
		case "State":
			// Format: "S (sleeping)"
			info.State = fields[1]
		case "Pid":
			info.PID, _ = strconv.Atoi(fields[1])
		case "PPid":
			info.PPID, _ = strconv.Atoi(fields[1])
		case "Threads":
			info.Threads, _ = strconv.Atoi(fields[1])
		case "VmRSS":
			rssKb, _ := strconv.Atoi(fields[1])
			info.RSSMB = float64(rssKb) / 1024
		case "VmSwap":
			swapKb, _ := strconv.Atoi(fields[1])
			info.SwapMB = float64(swapKb) / 1024
		}
	}
}

// procUptimeSec returns process uptime in seconds using /proc/PID/stat + /proc/uptime.
func procUptimeSec(base string) int {
	data, err := os.ReadFile(base + "/stat") // #nosec G304
	if err != nil {
		return 0
	}
	// stat format: pid (name) state ppid ... starttime(22nd field)
	// Name may contain spaces — find closing ')' first
	raw := string(data)
	rp := strings.LastIndex(raw, ")")
	if rp < 0 {
		return 0
	}
	fields := strings.Fields(raw[rp+2:])
	if len(fields) < 20 {
		return 0
	}
	startJiffies, _ := strconv.ParseInt(fields[19], 10, 64)
	if startJiffies == 0 {
		return 0
	}

	// System uptime from /proc/uptime
	upData, err := os.ReadFile("/proc/uptime") // #nosec G304
	if err != nil {
		return 0
	}
	upFields := strings.Fields(string(upData))
	if len(upFields) < 1 {
		return 0
	}
	uptimeSec, _ := strconv.ParseFloat(upFields[0], 64)

	// jiffies per second (HZ) — typically 100 on modern kernels
	hz := 100.0
	startSec := float64(startJiffies) / hz
	processAge := uptimeSec - startSec
	if processAge < 0 {
		return 0
	}
	return int(processAge)
}

// procCPUSec returns total CPU time (user+system) in seconds.
func procCPUSec(base string) float64 {
	data, err := os.ReadFile(base + "/stat") // #nosec G304
	if err != nil {
		return 0
	}
	raw := string(data)
	rp := strings.LastIndex(raw, ")")
	if rp < 0 {
		return 0
	}
	fields := strings.Fields(raw[rp+2:])
	if len(fields) < 14 {
		return 0
	}
	utime, _ := strconv.ParseFloat(fields[11], 64)
	stime, _ := strconv.ParseFloat(fields[12], 64)
	return (utime + stime) / 100.0 // divide by HZ=100
}

// procFDInfo returns (count, limit) for open file descriptors.
func procFDInfo(base string) (count, limit int) {
	fds, err := os.ReadDir(base + "/fd")
	if err == nil {
		count = len(fds)
	}
	// Limit from /proc/PID/limits
	if data, err := os.ReadFile(base + "/limits"); err == nil { // #nosec G304
		for _, line := range strings.Split(string(data), "\n") {
			if strings.HasPrefix(line, "Max open files") {
				fields := strings.Fields(line)
				// "Max open files  <soft>  <hard>  files"
				if len(fields) >= 4 {
					limit, _ = strconv.Atoi(fields[3])
				}
				break
			}
		}
	}
	return
}

// procMemMap reads /proc/PID/smaps_rollup (preferred) or sums /proc/PID/smaps.
func procMemMap(base string) *models.ProcMemMap {
	m := &models.ProcMemMap{}

	// Try smaps_rollup first (kernel 4.14+)
	data, err := os.ReadFile(base + "/smaps_rollup") // #nosec G304
	if err != nil {
		// Fall back to smaps
		data, err = os.ReadFile(base + "/smaps") // #nosec G304
		if err != nil {
			return nil
		}
	}

	for _, line := range strings.Split(string(data), "\n") {
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		val, _ := strconv.Atoi(fields[1])
		switch strings.TrimSuffix(fields[0], ":") {
		case "Rss":
			m.RSSKb = val
		case "Pss_Dirty":
			m.PssDirtyKb = val
		case "Private_Dirty":
			m.PrivateDirtyKb = val
		case "Private_Clean":
			m.PrivateCleanKb = val
		case "Shared_Clean":
			m.SharedCleanKb = val
		case "Shared_Dirty":
			m.SharedDirtyKb = val
		case "Swap":
			m.SwapKb = val
		}
	}
	return m
}

// procUser reads /proc/PID/status Uid field and resolves to username.
func procUser(base string) string {
	data, err := os.ReadFile(base + "/status") // #nosec G304
	if err != nil {
		return ""
	}
	for _, line := range strings.Split(string(data), "\n") {
		if !strings.HasPrefix(line, "Uid:") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 2 {
			break
		}
		uid := fields[1]
		// Look up username from /etc/passwd
		if passwd, err := os.ReadFile("/etc/passwd"); err == nil { // #nosec G304
			for _, pline := range strings.Split(string(passwd), "\n") {
				parts := strings.SplitN(pline, ":", 4)
				if len(parts) >= 4 && parts[2] == uid {
					return parts[0]
				}
			}
		}
		return "uid:" + uid
	}
	return ""
}

// collectOpenFiles reads /proc/PID/fd symlinks and categorises each entry.
// Returns a set of socket inodes for connection lookup.
func collectOpenFiles(base string, info *models.ProcInfo) map[string]bool {
	inodes := map[string]bool{}
	fdDir := base + "/fd"
	entries, err := os.ReadDir(fdDir)
	if err != nil {
		return inodes // requires same UID or root
	}

	for _, e := range entries {
		fd, _ := strconv.Atoi(e.Name())
		target, err := os.Readlink(fdDir + "/" + e.Name())
		if err != nil {
			continue
		}

		pf := models.ProcOpenFile{FD: fd, Target: target}
		pf.Deleted = strings.Contains(target, "(deleted)")

		switch {
		case strings.HasPrefix(target, "socket:["):
			pf.Type = "socket"
			inode := target[8 : len(target)-1]
			inodes[inode] = true
			info.SocketCount++
			// Check for deleted .so files (important signal: updated package, stale process)
		case strings.HasSuffix(target, ".so") || strings.Contains(target, ".so."):
			pf.Type = "file"
			info.FileCount++
			if pf.Deleted {
				info.DeletedLibs = append(info.DeletedLibs, filepath.Base(target))
			}
		case strings.HasPrefix(target, "pipe:["):
			pf.Type = "pipe"
			info.PipeCount++
		case strings.HasPrefix(target, "/"):
			pf.Type = "file"
			info.FileCount++
		default:
			pf.Type = "anon"
		}

		info.OpenFiles = append(info.OpenFiles, pf)
	}
	return inodes
}

// procNetConns reads /proc/net/tcp[6] and returns connections
// belonging to this process's socket inodes.
func procNetConns(inodes map[string]bool) []models.ProcNetConn {
	if len(inodes) == 0 {
		return nil
	}
	var conns []models.ProcNetConn
	for _, proto := range []string{"tcp", "tcp6"} {
		path := "/proc/net/" + proto
		f, err := os.Open(path) // #nosec G304
		if err != nil {
			continue
		}
		scanner := bufio.NewScanner(f)
		scanner.Scan() // skip header
		for scanner.Scan() {
			fields := strings.Fields(scanner.Text())
			if len(fields) < 10 {
				continue
			}
			inode := fields[9]
			if !inodes[inode] {
				continue
			}
			local := hexToAddr(fields[1])
			remote := hexToAddr(fields[2])
			state := tcpState(fields[3])
			conns = append(conns, models.ProcNetConn{
				Protocol:   proto,
				LocalAddr:  local,
				RemoteAddr: remote,
				State:      state,
			})
		}
		f.Close() //nolint:errcheck
	}
	return conns
}

// hexToAddr converts a /proc/net/tcp hex address:port to "IP:port" notation.
// IPv4: "0100007F:0050" → "127.0.0.1:80"
// IPv6: 32-char hex
func hexToAddr(s string) string {
	parts := strings.SplitN(s, ":", 2)
	if len(parts) != 2 {
		return s
	}
	addrHex, portHex := parts[0], parts[1]
	port64, _ := strconv.ParseInt(portHex, 16, 32)
	port := int(port64)

	if len(addrHex) == 8 {
		// IPv4 — little-endian bytes
		addr, _ := strconv.ParseInt(addrHex, 16, 64)
		return fmt.Sprintf("%d.%d.%d.%d:%d",
			addr&0xff, (addr>>8)&0xff, (addr>>16)&0xff, (addr>>24)&0xff, port)
	}
	// IPv6 — return shortened hex
	return fmt.Sprintf("[%s]:%d", addrHex, port)
}

// tcpState converts /proc/net/tcp state hex to a human-readable name.
var tcpStates = map[string]string{
	"01": "ESTABLISHED", "02": "SYN_SENT", "03": "SYN_RECV",
	"04": "FIN_WAIT1", "05": "FIN_WAIT2", "06": "TIME_WAIT",
	"07": "CLOSE", "08": "CLOSE_WAIT", "09": "LAST_ACK",
	"0A": "LISTEN", "0B": "CLOSING",
}

func tcpState(hex string) string {
	if s, ok := tcpStates[strings.ToUpper(hex)]; ok {
		return s
	}
	return hex
}
