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
	"github.com/keyorixhq/dashdiag/internal/platform"
)

const (
	kmsgPath          = "/dev/kmsg"
	journalRunPath    = "/run/log/journal"
	journalVarPath    = "/var/log/journal"
	crashLoopRestarts = 5
	// systemd's NRestarts counter is cumulative and never resets, so a unit that
	// crash-looped and was given up on stays NRestarts>=N forever. Only treat a
	// failed unit as a *live* crash loop if its last state change is within this
	// window; older failures are already surfaced by the systemd "unit failed"
	// insight, and reporting them as a current crash loop is misleading.
	crashLoopRecencyWindow = time.Hour
)

type LogsCollector struct {
	Lookback time.Duration
	profile  platform.Profile
}

func NewLogsCollector() *LogsCollector {
	return &LogsCollector{Lookback: 1 * time.Hour}
}

func NewLogsCollectorWithLookback(d time.Duration) *LogsCollector {
	return &LogsCollector{Lookback: d}
}

// NewLogsCollectorWithProfile builds a collector that uses the platform Profile
// to skip text-syslog probes on journald-only distros (NixOS, SteamOS).
func NewLogsCollectorWithProfile(p platform.Profile) *LogsCollector {
	return &LogsCollector{Lookback: 1 * time.Hour, profile: p}
}

func (c *LogsCollector) Name() string           { return "Logs" }
func (c *LogsCollector) Timeout() time.Duration { return 10 * time.Second }

func (c *LogsCollector) Collect(ctx context.Context) (interface{}, error) {
	info := &models.LogsInfo{Available: true}

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
	checkJournalHealth(ctx, info, c.profile)

	// Severity summary from journal (Spec 3)
	collectSeveritySummary(ctx, info, c.Lookback)

	// Crash file detection (Spec 3)
	collectCrashFiles(info)

	// Log source detection
	info.LogSource = detectLogSource(c.profile)

	// /var/log fallback: when the journal is volatile (lost on reboot) and gave
	// us no errors, pull the severity summary from /var/log instead (Spec 3).
	if info.ErrorCount == 0 && info.JournalVolatile {
		collectVarLogErrors(info)
	}

	// On a VM/cloud guest the NVMe device is virtual storage, so an I/O timeout
	// is a hypervisor/cloud-storage event, not a failing physical drive — the
	// analysis layer downgrades the NVMe insights accordingly.
	info.Virtualized = detectVirtualized(ctx)

	return info, nil
}

// detectVirtualized reports whether we are a VM/cloud guest (not bare metal).
// `systemd-detect-virt -v` reports only VMs (kvm/qemu/vmware/microsoft/amazon/
// xen/oracle/...) and exits non-zero with "none" on bare metal or in a
// container. The DMI-based VMware check is the no-systemd fallback.
func detectVirtualized(ctx context.Context) bool {
	if out, err := runCmd(ctx, "systemd-detect-virt", "-v"); err == nil {
		return isVMVirtType(strings.TrimSpace(out))
	}
	return VMwareGuestAvailable()
}

// isVMVirtType classifies systemd-detect-virt output: a VM type → true; "none"
// or a container type → false (a container shares the host kernel, so the
// "NVMe is virtual" reasoning doesn't apply).
func isVMVirtType(s string) bool {
	switch s {
	case "", "none",
		"lxc", "lxc-libvirt", "systemd-nspawn", "docker", "podman", "rkt", "wsl", "proot", "openvz":
		return false
	default:
		return true
	}
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

		// NVMe I/O timeout: "nvme nvme0: I/O 1 (I/O Cmd) QID 3 timeout, aborting"
		// This is the #1 NVMe failure indicator — precedes controller resets and system freezes.
		if strings.Contains(msgLower, "nvme") && strings.Contains(msgLower, "timeout") {
			info.NVMeTimeouts++
		}

		// NVMe controller reset/down: "nvme nvme0: controller is down; will reset: CSTS=0xffffffff"
		// or "nvme nvme0: I/O 0 QID 3 timeout, reset controller"
		if strings.Contains(msgLower, "nvme") &&
			(strings.Contains(msgLower, "reset controller") ||
				strings.Contains(msgLower, "controller is down") ||
				strings.Contains(msgLower, "csts=0xffffffff")) {
			info.NVMeResets++
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
		// Check NRestarts + recency via systemctl show.
		showOut, err := runCmd(ctx, "systemctl", "show", unit,
			"--property=NRestarts", "--property=InactiveEnterTimestamp")
		if err != nil {
			continue
		}
		var restarts int
		var inactiveEnter string
		for _, l := range strings.Split(showOut, "\n") {
			switch {
			case strings.HasPrefix(l, "NRestarts="):
				restarts, _ = strconv.Atoi(strings.TrimPrefix(l, "NRestarts="))
			case strings.HasPrefix(l, "InactiveEnterTimestamp="):
				inactiveEnter = strings.TrimPrefix(l, "InactiveEnterTimestamp=")
			}
		}
		if restarts < crashLoopRestarts {
			continue
		}
		// Skip stale loops: a unit given up on long ago is not currently looping
		// (the systemd "unit failed" insight still flags it). Wall-clock based so
		// it stays correct inside lxcfs containers, where CLOCK_MONOTONIC and
		// /proc/uptime disagree.
		if !crashLoopRecent(inactiveEnter, crashLoopRecencyWindow) {
			continue
		}
		loops = append(loops, fmt.Sprintf("%s (restarted %d times)", unit, restarts))
	}
	return loops
}

// crashLoopRecent reports whether a failed unit's last state change (systemd's
// InactiveEnterTimestamp, a wall-clock string like "Thu 2026-06-04 00:35:21 UTC")
// falls within window. Blank or unparseable timestamps return true — conservative:
// never hide a possibly-live crash loop. A timestamp that parses to the future
// (zone misparse / clock skew) also returns true for the same reason.
func crashLoopRecent(inactiveEnter string, window time.Duration) bool {
	inactiveEnter = strings.TrimSpace(inactiveEnter)
	if inactiveEnter == "" {
		return true
	}
	t, err := time.Parse("Mon 2006-01-02 15:04:05 MST", inactiveEnter)
	if err != nil {
		return true
	}
	age := time.Since(t)
	return age < 0 || age <= window
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
func checkJournalHealth(ctx context.Context, info *models.LogsInfo, profile platform.Profile) {
	// 1. Journal integrity — only verify archived (*.journal~) files, not active
	//    ones. journalctl --verify races with active writers and produces false
	//    corruption reports on healthy live journals (systemd issue #35916).
	if _, err := os.Stat(journalVarPath); err == nil {
		if hasCorruptArchived(journalVarPath) {
			info.JournalCorrupt = true
		}
	}

	// 2. Volatile storage — logs lost on reboot.
	info.JournalVolatile = detectVolatileJournal()

	// 3. Rate limiting — logs silently dropped under load.
	info.JournalRateLimited = detectJournalRateLimit()

	// 4. No text fallback.
	info.JournalNoTextFallback = detectNoTextFallback(profile)

	// 5. Unbounded growth — no SystemMaxUse cap and journal already large.
	info.JournalUnbounded = detectUnboundedJournal(info.JournalSizeGB)

	// 6. Sync interval risk — high SyncIntervalSec means final log lines from
	//    a crashing process may never be flushed to disk (Quote 6/7 from research).
	//    Default is 5 minutes — warn if > 60 seconds on a non-volatile journal.
	info.JournalSyncRisk = detectSyncRisk(info.JournalVolatile)

	// 7. Log disk space — check the volume where journals live.
	mount, pct := logDiskUsage()
	info.LogDiskMount = mount
	info.LogDiskUsedPct = pct
}

// hasCorruptArchived checks only archived (*.journal~) files for corruption.
// Active *.journal files are skipped — they're written live and always appear
// "corrupt" to the verifier due to an unflushed tail segment (systemd#35916).
func hasCorruptArchived(dir string) bool {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return false
	}
	for _, e := range entries {
		if e.IsDir() {
			// recurse into machine-ID subdirectories
			sub := dir + "/" + e.Name()
			if hasCorruptArchived(sub) {
				return true
			}
			continue
		}
		// Only check archived files (*.journal~), skip active (*.journal)
		if !strings.HasSuffix(e.Name(), ".journal~") {
			continue
		}
		// Run journalctl --verify on this specific file
		ctx2, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		out, err := runCmd(ctx2, "journalctl", "--verify", "--file="+dir+"/"+e.Name())
		cancel()
		if err != nil || strings.Contains(out, "FAIL") {
			return true
		}
	}
	return false
}

// detectUnboundedJournal returns true when no SystemMaxUse cap is configured
// and the journal is already large enough to matter (> 1 GB).
func detectUnboundedJournal(sizeGB float64) bool {
	if sizeGB < 1.0 {
		return false // small journal, not a concern yet
	}
	val := readJournaldConfig("SystemMaxUse")
	return strings.TrimSpace(val) == ""
}

// detectSyncRisk returns true when SyncIntervalSec is high enough that final
// log lines from a crashing process risk being lost. The default is 5 minutes
// (300s) — any value > 60s on a persistent journal is a risk.
// Volatile journals are excluded — they already lose logs on reboot anyway.
func detectSyncRisk(volatile bool) bool {
	if volatile {
		return false // volatile journal already loses logs on reboot
	}
	val := readJournaldConfig("SyncIntervalSec")
	val = strings.TrimSpace(val)
	if val == "" {
		// Default is 5 minutes — always a risk for crash scenarios
		return true
	}
	// Parse value — may be plain seconds or systemd time spec (e.g. "5min")
	secs := parseSystemdTime(val)
	return secs > 60
}

// parseSystemdTime parses a systemd time span string into seconds.
// Supports: plain integers (seconds), "Xs", "Xmin", "Xm", "Xh".
func parseSystemdTime(s string) int {
	s = strings.ToLower(strings.TrimSpace(s))
	if strings.HasSuffix(s, "min") {
		n, _ := strconv.Atoi(strings.TrimSuffix(s, "min"))
		return n * 60
	}
	if strings.HasSuffix(s, "m") {
		n, _ := strconv.Atoi(strings.TrimSuffix(s, "m"))
		return n * 60
	}
	if strings.HasSuffix(s, "h") {
		n, _ := strconv.Atoi(strings.TrimSuffix(s, "h"))
		return n * 3600
	}
	if strings.HasSuffix(s, "s") {
		n, _ := strconv.Atoi(strings.TrimSuffix(s, "s"))
		return n
	}
	n, _ := strconv.Atoi(s)
	return n
}

// logDiskUsage returns the mount point and used% of the filesystem containing
// the journal. Falls back to /var/log, then /.
func logDiskUsage() (mount string, usedPct float64) {
	// Prefer the actual journal directory
	target := journalVarPath
	if _, err := os.Stat(target); err != nil {
		target = "/var/log"
	}

	var stat syscall.Statfs_t
	if err := syscall.Statfs(target, &stat); err != nil {
		return "", 0
	}
	if stat.Blocks == 0 {
		return "", 0
	}
	used := float64(stat.Blocks-stat.Bfree) / float64(stat.Blocks) * 100
	// Find mount point by walking up the path
	mp := findMountPoint(target)
	return mp, used
}

// findMountPoint walks up from path until it finds a directory on a different
// device (i.e. a mount point boundary).
func findMountPoint(path string) string {
	var prev syscall.Stat_t
	if err := syscall.Stat(path, &prev); err != nil {
		return path
	}
	for {
		parent := filepath.Dir(path)
		if parent == path {
			return path // reached /
		}
		var pstat syscall.Stat_t
		if err := syscall.Stat(parent, &pstat); err != nil {
			return path
		}
		if pstat.Dev != prev.Dev {
			return path // path is the mount point
		}
		path = parent
		prev = pstat
	}
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
func detectNoTextFallback(profile platform.Profile) bool {
	// NixOS and SteamOS are journald-only by design — there is no text
	// fallback to find, and probing /var/log is pure noise. Treat as no-fallback
	// directly without the filesystem/service checks below.
	if profile.Distro == "nixos" || profile.Distro == "steamos" {
		return true
	}
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

// lookbackToSince converts a time.Duration to a journalctl --since string.
// journalctl accepts "X hours ago", "X minutes ago", "X days ago".
func lookbackToSince(d time.Duration) string {
	switch {
	case d >= 24*time.Hour:
		return fmt.Sprintf("%d days ago", int(d.Hours()/24))
	case d >= time.Hour:
		return fmt.Sprintf("%d hours ago", int(d.Hours()))
	default:
		return fmt.Sprintf("%d minutes ago", int(d.Minutes()))
	}
}

// ── Severity summary (Spec 3) ─────────────────────────────────────────────────

// collectSeveritySummary reads error and warning counts from the journal
// for the last hour using journalctl priority filters.
// Priority levels: 0=emerg 1=alert 2=crit 3=err 4=warning
func collectSeveritySummary(ctx context.Context, info *models.LogsInfo, lookback time.Duration) {
	summaryCtx, cancel := context.WithTimeout(ctx, 4*time.Second)
	defer cancel()

	since := lookbackToSince(lookback)

	// Error count: emerg(0) through err(3).
	errOut, err := runCmd(summaryCtx, "journalctl", "-p", "err", "--since", since,
		"--no-pager", "-q", "--output=short-iso")
	if err == nil {
		lines := strings.Split(strings.TrimSpace(errOut), "\n")
		msgCounts := make(map[string]int)
		entries := make([]models.TopError, 0, len(lines))
		now := time.Now()
		for _, line := range lines {
			if line == "" {
				continue
			}
			info.ErrorCount++
			// Extract message part (after host and unit) for deduplication
			key := logMessageKey(line)
			msgCounts[key]++
			if e, ok := parseJournalTopError(line, now); ok {
				entries = append(entries, e)
			}
		}
		// Top 5 most frequent errors (legacy string form)
		info.TopErrors = topMessages(msgCounts, 5)
		// Top 5 most recent errors with source + age (structured form)
		info.TopCritical = topErrorEntries(entries, 5)
	}

	// Warning count
	warnOut, err := runCmd(summaryCtx, "journalctl", "-p", "warning", "--since", since,
		"--no-pager", "-q", "--output=short")
	if err == nil {
		for _, line := range strings.Split(strings.TrimSpace(warnOut), "\n") {
			if line != "" {
				info.WarningCount++
			}
		}
		// Subtract errors from warning count (journalctl -p warning includes everything <= warning)
		info.WarningCount -= info.ErrorCount
		if info.WarningCount < 0 {
			info.WarningCount = 0
		}
	}
}

// logMessageKey extracts a short deduplicated key from a journal log line.
// Format: "May 19 10:00:00 hostname unit[pid]: message"
// We keep the unit + first 60 chars of message.
func logMessageKey(line string) string {
	fields := strings.Fields(line)
	// Skip date(0) time(1) host(2), take from field 3 onward
	if len(fields) > 3 {
		return truncateRunes(strings.Join(fields[3:], " "), 80)
	}
	return line
}

// topMessages returns the top N most frequent message keys.
func topMessages(counts map[string]int, n int) []string {
	type kv struct {
		key   string
		count int
	}
	var sorted []kv
	for k, v := range counts {
		sorted = append(sorted, kv{k, v})
	}
	// Simple insertion sort — message map is small
	for i := 1; i < len(sorted); i++ {
		for j := i; j > 0 && sorted[j].count > sorted[j-1].count; j-- {
			sorted[j], sorted[j-1] = sorted[j-1], sorted[j]
		}
	}
	var result []string
	for i := 0; i < len(sorted) && i < n; i++ {
		if sorted[i].count > 1 {
			result = append(result, fmt.Sprintf("×%d %s", sorted[i].count, sorted[i].key))
		} else {
			result = append(result, sorted[i].key)
		}
	}
	return result
}

const topErrorMsgCap = 120 // truncate long messages in structured top-error entries

// parseJournalTopError parses one `journalctl --output=short-iso` line into a
// structured TopError. Format: "2026-06-03T19:16:09+00:00 host unit[pid]: message".
// The timestamp is RFC3339 (offset carries a colon, e.g. "+00:00").
func parseJournalTopError(line string, now time.Time) (models.TopError, bool) {
	fields := strings.Fields(line)
	if len(fields) < 4 {
		return models.TopError{}, false
	}
	// short-iso fields: [0]=timestamp [1]=host [2]=source [3:]=message
	source, msg := sourceAndMessage(fields, 3)
	if msg == "" {
		return models.TopError{}, false
	}
	age := -1
	if t, err := time.Parse(time.RFC3339, fields[0]); err == nil {
		age = ageMinutes(now, t)
	}
	return models.TopError{Message: msg, Source: source, AgeMin: age}, true
}

// parseSyslogTopError parses one traditional /var/log line into a TopError.
// Format: "Jun  3 10:30:00 host process[pid]: message" (no year in the stamp).
func parseSyslogTopError(line string, now time.Time) (models.TopError, bool) {
	fields := strings.Fields(line)
	if len(fields) < 6 {
		return models.TopError{}, false
	}
	// syslog fields: [0]=month [1]=day [2]=time [3]=host [4]=source [5:]=message
	source, msg := sourceAndMessage(fields, 5)
	if msg == "" {
		return models.TopError{}, false
	}
	age := -1
	stamp := strings.Join(fields[0:3], " ") // "Jun 3 10:30:00"
	if t, err := time.Parse("Jan 2 15:04:05", stamp); err == nil {
		t = t.AddDate(now.Year(), 0, 0) // syslog stamp has no year — assume current
		age = ageMinutes(now, t)
	}
	return models.TopError{Message: msg, Source: source, AgeMin: age}, true
}

// sourceAndMessage extracts the source (the token before the message, stripped
// of "[pid]" and trailing ":") and the joined message starting at msgStart.
func sourceAndMessage(fields []string, msgStart int) (source, message string) {
	if msgStart >= len(fields) {
		return "", ""
	}
	source = strings.TrimSuffix(fields[msgStart-1], ":")
	if i := strings.IndexByte(source, '['); i >= 0 {
		source = source[:i]
	}
	message = strings.Join(fields[msgStart:], " ")
	if len(message) > topErrorMsgCap {
		message = message[:topErrorMsgCap]
	}
	return source, message
}

// ageMinutes returns whole minutes between t and now, clamped at 0.
func ageMinutes(now, t time.Time) int {
	m := int(now.Sub(t).Minutes())
	if m < 0 {
		return 0
	}
	return m
}

// topErrorEntries deduplicates by message keeping the most recent occurrence,
// and returns up to n entries newest-first. journalctl/syslog emit oldest-first,
// so iterating in reverse yields newest-first naturally.
func topErrorEntries(entries []models.TopError, n int) []models.TopError {
	seen := make(map[string]bool, len(entries))
	out := make([]models.TopError, 0, n)
	for i := len(entries) - 1; i >= 0 && len(out) < n; i-- {
		e := entries[i]
		if seen[e.Message] {
			continue
		}
		seen[e.Message] = true
		out = append(out, e)
	}
	return out
}

// ── Crash file detection (Spec 3) ────────────────────────────────────────────

// collectCrashFiles scans known crash dump locations for core files and
// crash reports. Sets CrashFiles and CoreDumpCount on the info struct.
//
// Locations checked:
//   - /var/crash/       — kernel crash dumps (kdump), some distros' apport output
//   - /var/lib/systemd/coredump/ — systemd-coredump managed core files
//   - /sys/fs/pstore/   — pstore panic records (read-only, from previous boot)
func collectCrashFiles(info *models.LogsInfo) {
	dirs := []string{
		"/var/crash",
		"/var/lib/systemd/coredump",
	}
	now := time.Now()

	for _, dir := range dirs {
		entries, err := os.ReadDir(dir)
		if err != nil {
			continue
		}
		for _, e := range entries {
			if e.IsDir() {
				continue
			}
			fi, err := e.Info()
			if err != nil {
				continue
			}
			// Only flag files from the last 30 days
			ageDays := int(now.Sub(fi.ModTime()).Hours() / 24)
			if ageDays > 30 {
				continue
			}
			cf := models.CrashFile{
				Path:    filepath.Join(dir, e.Name()),
				SizeMB:  float64(fi.Size()) / (1024 * 1024),
				AgeDays: ageDays,
			}
			info.CrashFiles = append(info.CrashFiles, cf)
			info.CoreDumpCount++
		}
	}

	// pstore — count panic records (each file is one event, filenames contain type)
	pstoreEntries, _ := os.ReadDir("/sys/fs/pstore")
	for _, e := range pstoreEntries {
		name := e.Name()
		if strings.Contains(name, "panic") || strings.Contains(name, "oops") ||
			strings.Contains(name, "dmesg") {
			fi, err := e.Info()
			if err != nil {
				continue
			}
			ageDays := int(now.Sub(fi.ModTime()).Hours() / 24)
			info.CrashFiles = append(info.CrashFiles, models.CrashFile{
				Path:    "/sys/fs/pstore/" + name,
				SizeMB:  float64(fi.Size()) / (1024 * 1024),
				AgeDays: ageDays,
			})
			info.CoreDumpCount++
		}
	}
}

// ── Log source detection ──────────────────────────────────────────────────────

// detectLogSource identifies what log infrastructure is active.
// Returns "journald", "journald+syslog", or "syslog".
func detectLogSource(profile platform.Profile) string {
	hasJournald := false
	if _, err := os.Stat("/run/systemd/journal/socket"); err == nil {
		hasJournald = true
	}
	// NixOS and SteamOS are journald-only — skip the text-syslog probe entirely.
	if profile.Distro == "nixos" || profile.Distro == "steamos" {
		if hasJournald {
			return "journald"
		}
		return "unknown"
	}
	// Check for syslog text files (common co-existence on Ubuntu/RHEL)
	hasSyslog := false
	for _, p := range []string{"/var/log/syslog", "/var/log/messages"} {
		if fi, err := os.Stat(p); err == nil && fi.Size() > 0 {
			hasSyslog = true
			break
		}
	}
	switch {
	case hasJournald && hasSyslog:
		return "journald+syslog"
	case hasJournald:
		return "journald"
	case hasSyslog:
		return "syslog"
	default:
		return "unknown"
	}
}

// ── /var/log error aggregation fallback (Spec 3) ─────────────────────────────

// varLogTailLines is how many trailing lines of /var/log we scan.
const varLogTailLines = 500

// collectVarLogErrors reads the last lines of /var/log/syslog or
// /var/log/messages and populates ErrorCount/TopErrors/TopCritical from them.
// Only called when journald is volatile and produced no errors, so it never
// duplicates journald output. Updates LogSource to the file used.
func collectVarLogErrors(info *models.LogsInfo) {
	collectVarLogErrorsFrom(info, []string{"/var/log/syslog", "/var/log/messages"})
}

// collectVarLogErrorsFrom is the testable core: it scans the first non-empty
// file in candidates. Production passes the two hardcoded system log paths.
func collectVarLogErrorsFrom(info *models.LogsInfo, candidates []string) {
	path, source := "", ""
	for _, p := range candidates {
		if fi, err := os.Stat(p); err == nil && fi.Size() > 0 {
			path = p
			source = filepath.Base(p) // "syslog" or "messages"
			break
		}
	}
	if path == "" {
		return
	}

	data, err := os.ReadFile(path) // #nosec G304 -- path comes from a controlled candidate list
	if err != nil {
		return
	}

	count, top, crit := scanVarLog(string(data), time.Now())
	// Record that we consulted /var/log even when it yields zero errors — this
	// is how the fallback is confirmable on a clean system (LogSource flips to
	// "messages"/"syslog"). The caller's ErrorCount==0 guard already prevents
	// this from running when journald produced its own errors.
	info.LogSource = source
	info.ErrorCount = count
	info.TopErrors = top
	info.TopCritical = crit
}

// varLogSeverityKeywords are the case-insensitive substrings that mark a line
// as an error/critical entry in traditional syslog text.
var varLogSeverityKeywords = []string{"error", "crit", "alert", "emerg", "err"}

// scanVarLog counts error lines in the last varLogTailLines lines of content
// and returns the count plus the top error messages (legacy + structured).
func scanVarLog(content string, now time.Time) (count int, top []string, crit []models.TopError) {
	lines := strings.Split(strings.TrimRight(content, "\n"), "\n")
	if len(lines) > varLogTailLines {
		lines = lines[len(lines)-varLogTailLines:]
	}

	msgCounts := make(map[string]int)
	entries := make([]models.TopError, 0, len(lines))
	for _, line := range lines {
		if !lineHasSeverity(line) {
			continue
		}
		count++
		msgCounts[logMessageKey(line)]++
		if e, ok := parseSyslogTopError(line, now); ok {
			entries = append(entries, e)
		}
	}
	if count == 0 {
		return 0, nil, nil
	}
	return count, topMessages(msgCounts, 5), topErrorEntries(entries, 5)
}

// lineHasSeverity reports whether a syslog line matches any severity keyword.
func lineHasSeverity(line string) bool {
	low := strings.ToLower(line)
	for _, kw := range varLogSeverityKeywords {
		if strings.Contains(low, kw) {
			return true
		}
	}
	return false
}
