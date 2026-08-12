//go:build linux

package collectors

import (
	"bufio"
	"context"
	"fmt"
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
		topProcs, _, _ := topMemoryProcs(15)
		info.TopProcs = topProcs
		return info, nil
	}
	return collectProcPID(c.PID)
}

// collectProcPID reads all /proc/<pid>/ files for a given PID.
func collectProcPID(pid int) (*models.ProcInfo, error) {
	base := fmt.Sprintf("/proc/%d", pid)

	// Verify PID exists
	if !fileExists(base) {
		return nil, fmt.Errorf("PID %d not found", pid)
	}

	info := &models.ProcInfo{PID: pid}

	// Status file — name, state, PPID, threads, FDSize, VmRSS, VmSwap
	parseProcStatus(base, info)

	// Cmdline
	if data, err := readFile(base + "/cmdline"); err == nil { // #nosec G304
		info.Cmdline = strings.ReplaceAll(
			strings.TrimRight(string(data), "\x00"), "\x00", " ")
		if len(info.Cmdline) > 200 {
			info.Cmdline = info.Cmdline[:200] + "…"
		}
	}

	// wchan — kernel function the process is blocked on
	if data, err := readFile(base + "/wchan"); err == nil { // #nosec G304
		info.WChan = strings.TrimSpace(string(data))
	}
	info.DState = info.State == "D"

	// Uptime via /proc/PID/stat field 22 (starttime in jiffies)
	info.UptimeSec = procUptimeSec(base)

	// CPU time from /proc/PID/stat fields 14+15 (utime+stime in jiffies)
	info.CPUSec = procCPUSec(base)

	// FD count and limit
	info.FDCount, info.FDLimit, info.FDReadable = procFDInfo(base)
	if info.FDReadable && info.FDLimit > 0 {
		info.FDPressure = float64(info.FDCount)/float64(info.FDLimit) > 0.80
	}

	// Memory map from smaps_rollup (kernel 4.14+) or smaps fallback
	info.MemMap = procMemMap(base)

	// Owner user
	info.User = procUser(base)

	// Parent name
	if info.PPID > 0 {
		if data, err := readFile(
			fmt.Sprintf("/proc/%d/comm", info.PPID)); err == nil { // #nosec G304
			info.ParentName = strings.TrimSpace(string(data))
		}
	}

	// Cgroup (last path component for readability)
	if data, err := readFile(base + "/cgroup"); err == nil { // #nosec G304
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

	// Network connections for this process's socket inodes. Best-effort like
	// the other fields above (cmdline, wchan, cgroup): a partial read still
	// yields whatever connections were parsed before the failure. The error
	// itself isn't fatal to the overall proc snapshot, so it isn't
	// propagated further, but scanner.Err() is no longer silently dropped
	// inside procNetConns itself.
	conns, _ := procNetConns(inodes)
	info.Connections = conns

	return info, nil
}

// parseProcStatus reads /proc/PID/status for key fields.
func parseProcStatus(base string, info *models.ProcInfo) {
	data, err := readFile(base + "/status") // #nosec G304
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
			// comm can contain spaces (e.g. "Web Content"), so take the rest of
			// the line rather than fields[1], which would truncate at the space.
			info.Name = strings.TrimSpace(strings.TrimPrefix(line, "Name:"))
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
	data, err := readFile(base + "/stat") // #nosec G304
	if err != nil {
		return 0
	}
	// stat format: pid (name) state ppid ... starttime(22nd field)
	// Name may contain spaces — find closing ')' first
	raw := string(data)
	rp := strings.LastIndex(raw, ")")
	// rp+2 skips ") " after the comm field; a stat line truncated right at (or
	// past) the closing paren — e.g. crafted/replayed content — must not slice
	// past the end of raw.
	if rp < 0 || rp+2 > len(raw) {
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
	upData, err := readFile("/proc/uptime") // #nosec G304
	if err != nil {
		return 0
	}
	upFields := strings.Fields(string(upData))
	if len(upFields) < 1 {
		return 0
	}
	uptimeSec := parseFloat(upFields[0])

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
	data, err := readFile(base + "/stat") // #nosec G304
	if err != nil {
		return 0
	}
	raw := string(data)
	rp := strings.LastIndex(raw, ")")
	// Same bounds guard as procUptimeSec: don't slice past the end of raw when
	// the stat line is truncated right at (or past) the closing paren.
	if rp < 0 || rp+2 > len(raw) {
		return 0
	}
	fields := strings.Fields(raw[rp+2:])
	if len(fields) < 14 {
		return 0
	}
	utime := parseFloat(fields[11])
	stime := parseFloat(fields[12])
	return (utime + stime) / 100.0 // divide by HZ=100
}

// procFDInfo returns (count, limit) for open file descriptors.
func procFDInfo(base string) (count, limit int, readable bool) {
	fds, err := readDirNames(base + "/fd")
	if err == nil {
		count = len(fds)
		readable = true
	}
	// Limit from /proc/PID/limits
	if data, err := readFile(base + "/limits"); err == nil { // #nosec G304
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
	data, err := readFile(base + "/smaps_rollup") // #nosec G304
	if err != nil {
		// Fall back to smaps
		data, err = readFile(base + "/smaps") // #nosec G304
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
	data, err := readFile(base + "/status") // #nosec G304
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
		if passwd, err := readFile("/etc/passwd"); err == nil { // #nosec G304
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
// isSharedLib reports whether path points at a shared object, matching on the
// base name so a versioned (libfoo.so.6) or unversioned (libfoo.so) library is
// recognised regardless of the directory it lives in.
func isSharedLib(path string) bool {
	base := filepath.Base(path)
	return strings.HasSuffix(base, ".so") || strings.Contains(base, ".so.")
}

func collectOpenFiles(base string, info *models.ProcInfo) map[string]bool {
	inodes := map[string]bool{}
	fdDir := base + "/fd"
	entries, err := readDirNames(fdDir)
	if err != nil {
		return inodes // requires same UID or root
	}

	for _, e := range entries {
		fd, _ := strconv.Atoi(e)
		target, err := readLink(fdDir + "/" + e)
		if err != nil {
			continue
		}

		pf := models.ProcOpenFile{FD: fd, Target: target}
		pf.Deleted = strings.Contains(target, "(deleted)")
		// readlink target for a deleted file is "<path> (deleted)"; strip the
		// suffix before classifying so an unversioned ".so (deleted)" still
		// matches and isn't silently filed under the generic "/" case.
		cleanTarget := strings.TrimSuffix(target, " (deleted)")

		switch {
		case strings.HasPrefix(target, "socket:["):
			pf.Type = "socket"
			// A well-formed target is "socket:[<inode>]" (kernel-generated), but
			// this string can also arrive via a replayed capture bundle, which is
			// untrusted input — a target that's exactly "socket:[" (no trailing
			// "]") would make the naive target[8:len-1] slice panic (start > end).
			if inode, ok := strings.CutSuffix(target[len("socket:["):], "]"); ok {
				inodes[inode] = true
			}
			info.SocketCount++
			// Check for deleted .so files (important signal: updated package, stale process)
		case isSharedLib(cleanTarget):
			pf.Type = "file"
			info.FileCount++
			if pf.Deleted {
				info.DeletedLibs = append(info.DeletedLibs, filepath.Base(cleanTarget))
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
// belonging to this process's socket inodes. Returns a non-nil error if any
// proto table was only partially read (best-effort: whatever was parsed
// before the failure, from either proto, is still returned).
func procNetConns(inodes map[string]bool) ([]models.ProcNetConn, error) {
	if len(inodes) == 0 {
		return nil, nil
	}
	var conns []models.ProcNetConn
	var readErr error
	for _, proto := range []string{"tcp", "tcp6"} {
		path := "/proc/net/" + proto
		f, err := openFile(path) // #nosec G304
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
		if err := scanner.Err(); err != nil && readErr == nil {
			// Partial/unreliable read of this proto's table — keep what was
			// parsed so far (best-effort, matching the rest of
			// collectProcPID's field population), but surface the failure
			// rather than silently dropping it.
			readErr = fmt.Errorf("scanning %s: %w", path, err)
		}
		f.Close() //nolint:errcheck
	}
	return conns, readErr
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
