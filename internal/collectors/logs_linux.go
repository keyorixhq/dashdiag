//go:build linux

package collectors

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/keyorixhq/dashdiag/internal/models"
)

const (
	kmsgPath          = "/dev/kmsg"
	journalRunPath    = "/run/log/journal"
	journalVarPath    = "/var/log/journal"
	crashLoopRestarts = 5
)

type LogsCollector struct {
	Lookback time.Duration
}

func NewLogsCollector() *LogsCollector {
	return &LogsCollector{Lookback: 1 * time.Hour}
}

func NewLogsCollectorWithLookback(d time.Duration) *LogsCollector {
	return &LogsCollector{Lookback: d}
}

func (c *LogsCollector) Name() string           { return "Logs" }
func (c *LogsCollector) Timeout() time.Duration { return 10 * time.Second }

func (c *LogsCollector) Collect(ctx context.Context) (interface{}, error) {
	info := &models.LogsInfo{}

	if os.Getuid() != 0 {
		info.NeedsRoot = true
	}

	done := make(chan struct{})
	go func() {
		kmsgCtx, kmsgCancel := context.WithTimeout(ctx, 500*time.Millisecond)
		defer kmsgCancel()
		parseKmsg(kmsgCtx, info, c.Lookback)
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(600 * time.Millisecond):
		// kmsg timed out — skip silently, don't block the health check
	}

	info.JournalSizeGB = journalDiskUsage()

	loopCtx, loopCancel := context.WithTimeout(ctx, 5*time.Second)
	defer loopCancel()
	info.CrashLoops = detectCrashLoops(loopCtx)

	// Check pstore for panic records from previous boots
	info.KernelPanics += countPstorePanics()

	// Journal health checks
	checkJournalHealth(ctx, info)

	return info, nil
}

// parseKmsg reads /dev/kmsg and extracts OOM kills and segfaults from the last hour.
// /dev/kmsg entries are: "priority,sequence,timestamp_usec,flags;message"
// timestamp_usec is monotonic time since boot in microseconds.
func parseKmsg(ctx context.Context, info *models.LogsInfo, lookback time.Duration) {
	f, err := os.OpenFile(kmsgPath, os.O_RDONLY|syscall.O_NONBLOCK, 0) // #nosec G304 -- hardcoded /dev/kmsg constant
	if err != nil {
		return
	}
	defer f.Close() //nolint:errcheck

	uptimeBytes, err := os.ReadFile("/proc/uptime")
	if err != nil {
		return
	}
	fields := strings.Fields(string(uptimeBytes))
	if len(fields) == 0 {
		return
	}
	uptimeSec, err := strconv.ParseFloat(fields[0], 64)
	if err != nil {
		return
	}
	nowUsec := uptimeSec * 1e6
	lookbackUsec := lookback.Seconds() * 1e6

	oomSeen := make(map[string]bool)
	segSeen := make(map[string]bool)

	buf := make([]byte, 8192)
	for {
		select {
		case <-ctx.Done():
			return
		default:
		}
		n, err := f.Read(buf)
		if n == 0 || err != nil {
			return // EAGAIN or EOF — ring buffer exhausted
		}
		line := strings.TrimRight(string(buf[:n]), "\n")

		// Format: "priority,seq,timestamp_usec,flags;message"
		semi := strings.IndexByte(line, ';')
		if semi < 0 {
			continue
		}
		meta := line[:semi]
		msg := line[semi+1:]

		metaParts := strings.SplitN(meta, ",", 4)
		if len(metaParts) < 3 {
			continue
		}
		tsUsec, err := strconv.ParseFloat(metaParts[2], 64)
		if err != nil {
			continue
		}
		if nowUsec-tsUsec > lookbackUsec {
			continue // outside lookback window
		}

		msgLower := strings.ToLower(msg)

		// OOM kill: "Out of memory: Kill process 1234 (nginx)"
		if strings.Contains(msgLower, "out of memory") && strings.Contains(msgLower, "kill") {
			proc := extractParenthesized(msg)
			if proc != "" && !oomSeen[proc] {
				oomSeen[proc] = true
				info.OOMProcesses = append(info.OOMProcesses, proc)
			}
			info.OOMKills++
		}

		// Segfault: "nginx[1234]: segfault at ..."
		if strings.Contains(msgLower, "segfault") {
			proc := extractBracketProc(msg)
			if proc != "" && !segSeen[proc] {
				segSeen[proc] = true
				info.SegfaultProcs = append(info.SegfaultProcs, proc)
			}
			info.Segfaults++
		}

		// Soft lockup: "BUG: soft lockup - CPU#0 stuck for 22s!"
		if strings.Contains(msgLower, "soft lockup") {
			info.SoftLockups++
		}

		// Hard lockup: "BUG: hard lockup on CPU 0" or NMI watchdog
		if strings.Contains(msgLower, "hard lockup") || strings.Contains(msgLower, "nmi watchdog: bug") {
			info.HardLockups++
		}

		// Kernel panic in kmsg (rare — usually in pstore after reboot)
		if strings.Contains(msgLower, "kernel panic") {
			info.KernelPanics++
		}
	}
}

// extractParenthesized extracts the first parenthesized word from a string.
// "Out of memory: Kill process 1234 (nginx) score" → "nginx"
func extractParenthesized(s string) string {
	open := strings.IndexByte(s, '(')
	if open < 0 {
		return ""
	}
	close := strings.IndexByte(s[open:], ')')
	if close < 0 {
		return ""
	}
	return strings.TrimSpace(s[open+1 : open+close])
}

// extractBracketProc extracts the process name before "[pid]" in kernel messages.
// "nginx[1234]: segfault at ..." → "nginx"
func extractBracketProc(s string) string {
	bracket := strings.IndexByte(s, '[')
	if bracket < 0 {
		return ""
	}
	name := strings.TrimSpace(s[:bracket])
	// Strip any leading path
	if idx := strings.LastIndexByte(name, '/'); idx >= 0 {
		name = name[idx+1:]
	}
	return name
}

// journalDiskUsage returns total journal size in GB by walking journal directories.
func journalDiskUsage() float64 {
	var total int64
	for _, dir := range []string{journalRunPath, journalVarPath} {
		_ = filepath.Walk(dir, func(_ string, fi os.FileInfo, err error) error {
			if err == nil && !fi.IsDir() {
				total += fi.Size()
			}
			return nil
		})
	}
	return float64(total) / (1024 * 1024 * 1024)
}

// detectCrashLoops uses systemctl to find units that have restarted frequently.
// This is an acceptable wrapper — crash loop state isn't in /proc or /sys.
func detectCrashLoops(ctx context.Context) []string {
	out, err := runCmd(ctx, "systemctl", "list-units", "--state=failed", "--no-legend", "--no-pager", "--plain")
	if err != nil {
		return nil
	}
	var loops []string
	for _, line := range strings.Split(out, "\n") {
		fields := strings.Fields(line)
		if len(fields) == 0 {
			continue
		}
		unit := fields[0]
		if !strings.Contains(unit, ".") {
			continue
		}
		// Skip known LXC/cloud-init false positives
		if cloudInitUnits[unit] {
			continue
		}
		// Handle template instances e.g. container-getty@1.service
		if at := strings.Index(unit, "@"); at >= 0 {
			if dot := strings.LastIndex(unit, "."); dot > at {
				if cloudInitUnits[unit[:at+1]+unit[dot:]] {
					continue
				}
			}
		}
		// Check NRestarts via systemctl show
		showOut, err := runCmd(ctx, "systemctl", "show", unit, "--property=NRestarts")
		if err != nil {
			continue
		}
		for _, l := range strings.Split(showOut, "\n") {
			if strings.HasPrefix(l, "NRestarts=") {
				n, _ := strconv.Atoi(strings.TrimPrefix(l, "NRestarts="))
				if n >= crashLoopRestarts {
					loops = append(loops, fmt.Sprintf("%s (restarted %d times)", unit, n))
				}
			}
		}
	}
	return loops
}

// countPstorePanics counts kernel panic dump files in /sys/fs/pstore.
// pstore files persist across reboots and are named dmesg-efi-*, dmesg-erst-*, etc.
// A panic file means the previous boot ended in a kernel panic.
// Returns 0 when pstore is not mounted or no panic files exist.
func countPstorePanics() int {
	entries, err := os.ReadDir("/sys/fs/pstore")
	if err != nil {
		return 0
	}
	count := 0
	for _, e := range entries {
		name := strings.ToLower(e.Name())
		// pstore panic files: dmesg-efi-NNN, dmesg-erst-NNN, dmesg-ramoops-NNN
		if strings.HasPrefix(name, "dmesg-") || strings.Contains(name, "panic") {
			count++
		}
	}
	return count
}

// checkJournalHealth checks for common journald misconfigurations that cause
// silent log loss — the most frequent complaint about systemd logging.
func checkJournalHealth(ctx context.Context, info *models.LogsInfo) {
	// 1. Journal integrity — journalctl --verify detects corrupted journal files.
	//    Only run if journalctl is available and journal exists.
	if _, err := os.Stat(journalVarPath); err == nil {
		out, err := runCmd(ctx, "journalctl", "--verify", "--quiet")
		if err != nil || strings.Contains(out, "FAIL") {
			info.JournalCorrupt = true
		}
	}

	// 2. Volatile storage — logs lost on reboot.
	//    Check Storage= in /etc/systemd/journald.conf and drop-ins.
	//    Default "auto" only persists if /var/log/journal/ exists.
	info.JournalVolatile = detectVolatileJournal()

	// 3. Rate limiting — logs silently dropped under load.
	//    Check if RateLimitBurst is very low (< 100) — default is 10000.
	//    A value of 0 means unlimited (actually fine), so only warn on low non-zero.
	info.JournalRateLimited = detectJournalRateLimit()

	// 4. No text fallback — if journald is sole log store, a corruption or
	//    binary format issue means no logs readable with standard Unix tools.
	info.JournalNoTextFallback = detectNoTextFallback()
}

// detectVolatileJournal returns true if journal logs will be lost on reboot.
func detectVolatileJournal() bool {
	// If /var/log/journal/ exists, journald will persist regardless of config.
	if _, err := os.Stat(journalVarPath); err == nil {
		return false
	}
	// /var/log/journal/ missing — check config to see if persistence is explicitly set.
	storage := readJournaldConfig("Storage")
	switch strings.ToLower(storage) {
	case "persistent":
		return false // explicitly configured, just missing the directory
	case "volatile", "none":
		return true
	default:
		// "auto" (default) or unset — no /var/log/journal/ = volatile
		return true
	}
}

// detectJournalRateLimit returns true if RateLimitBurst is set dangerously low.
func detectJournalRateLimit() bool {
	val := readJournaldConfig("RateLimitBurst")
	if val == "" {
		return false // default (10000) is fine
	}
	n, err := strconv.Atoi(strings.TrimSpace(val))
	if err != nil {
		return false
	}
	// 0 = unlimited (fine), < 100 = suspiciously low (logs will be dropped)
	return n > 0 && n < 100
}

// detectNoTextFallback returns true when journald is the sole log sink —
// no rsyslog, syslog-ng, or /var/log/syslog text file present.
func detectNoTextFallback() bool {
	// If a text syslog file exists, there is a fallback.
	for _, f := range []string{"/var/log/syslog", "/var/log/messages", "/var/log/auth.log"} {
		if _, err := os.Stat(f); err == nil {
			return false
		}
	}
	// Check if rsyslog or syslog-ng is running.
	for _, svc := range []string{"rsyslog", "syslog-ng", "syslogd"} {
		if isServiceActive(svc) {
			return false
		}
	}
	return true
}

// readJournaldConfig reads a single key from journald.conf and its drop-ins.
// Drop-ins in /etc/systemd/journald.conf.d/*.conf take precedence.
func readJournaldConfig(key string) string {
	var result string
	files := []string{"/etc/systemd/journald.conf"}
	if entries, err := os.ReadDir("/etc/systemd/journald.conf.d"); err == nil {
		for _, e := range entries {
			if strings.HasSuffix(e.Name(), ".conf") {
				files = append(files, "/etc/systemd/journald.conf.d/"+e.Name())
			}
		}
	}
	prefix := key + "="
	for _, path := range files {
		b, err := os.ReadFile(path) // #nosec G304
		if err != nil {
			continue
		}
		for _, line := range strings.Split(string(b), "\n") {
			line = strings.TrimSpace(line)
			if strings.HasPrefix(line, "#") {
				continue
			}
			if strings.HasPrefix(line, prefix) {
				result = strings.TrimPrefix(line, prefix)
			}
		}
	}
	return result
}

// isServiceActive checks if a systemd service is currently active.
func isServiceActive(name string) bool {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	out, err := runCmd(ctx, "systemctl", "is-active", name)
	return err == nil && strings.TrimSpace(out) == "active"
}
