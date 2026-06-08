//go:build linux

package collectors

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/keyorixhq/dashdiag/internal/models"
)

// TimelineCollector merges journal errors, dmesg kernel events, and load
// spikes into a single chronological incident timeline.
type TimelineCollector struct {
	WindowHours int // how many hours back to look (default 1)
}

func NewTimelineCollector(hours int) *TimelineCollector {
	if hours <= 0 {
		hours = 1
	}
	return &TimelineCollector{WindowHours: hours}
}

func (c *TimelineCollector) Name() string           { return "Timeline" }
func (c *TimelineCollector) Timeout() time.Duration { return 20 * time.Second }

func (c *TimelineCollector) Collect(ctx context.Context) (interface{}, error) {
	info := &models.TimelineInfo{WindowHours: c.WindowHours}
	since := time.Now().Add(-time.Duration(c.WindowHours) * time.Hour)

	// Collect from each source in parallel
	type result struct {
		events []models.TimelineEvent
		err    error
	}
	jCh := make(chan result, 1)
	dCh := make(chan result, 1)

	go func() {
		events, err := collectJournalEvents(ctx, since)
		jCh <- result{events, err}
	}()
	go func() {
		events, err := collectDmesgEvents(ctx, since)
		dCh <- result{events, err}
	}()

	jr := <-jCh
	dr := <-dCh

	info.Events = append(info.Events, jr.events...)
	info.Events = append(info.Events, dr.events...)

	// Load average spikes from /proc/loadavg (current) + journald cpu pressure events
	info.LoadSpikes = collectLoadSpikes(ctx, since)

	// Sort all events chronologically
	sort.Slice(info.Events, func(i, j int) bool {
		return info.Events[i].TimestampUnix < info.Events[j].TimestampUnix
	})

	// Deduplicate: same unit+message within the same minute → collapse to one entry
	info.Events = deduplicateEvents(info.Events)

	// Annotate known patterns with inspect/fix hints
	info.Events = annotateHints(info.Events)

	// Cap at 200 events — show the most significant
	if len(info.Events) > 200 {
		info.Events = filterTopEvents(info.Events, 200)
	}

	for _, e := range info.Events {
		switch e.Level {
		case "CRIT":
			info.CritCount++
		case "WARN":
			info.WarnCount++
		}
	}

	return info, nil
}

// ── journal events ────────────────────────────────────────────────────────────

// collectJournalEvents reads error/warning entries from journald as JSON.
func collectJournalEvents(ctx context.Context, since time.Time) ([]models.TimelineEvent, error) {
	sinceStr := since.Format("2006-01-02 15:04:05")
	jCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	// Use JSON output for reliable field extraction
	args := []string{
		"journalctl", "--no-pager", "--output=json",
		"--since", sinceStr,
		"--priority=warning", // 0–4: emerg/alert/crit/err/warning
	}
	cmd := localeSafeCmd(jCtx, args[0], args[1:]...) // #nosec G204
	out, err := cmd.Output()
	if err != nil {
		return nil, nil // journalctl unavailable — silent
	}

	var events []models.TimelineEvent
	for _, line := range strings.Split(strings.TrimSpace(string(out)), "\n") {
		if line == "" {
			continue
		}
		ev := parseJournalLine(line)
		if ev != nil {
			events = append(events, *ev)
		}
		if len(events) >= 500 {
			break
		}
	}
	return events, nil
}

// parseJournalLine parses one JSON journal line into a TimelineEvent.
func parseJournalLine(line string) *models.TimelineEvent {
	var entry struct {
		RealtimeTimestamp string `json:"__REALTIME_TIMESTAMP"`
		Priority          string `json:"PRIORITY"`
		SyslogID          string `json:"SYSLOG_IDENTIFIER"`
		SystemdUnit       string `json:"_SYSTEMD_UNIT"`
		Message           string `json:"MESSAGE"`
		Comm              string `json:"_COMM"`
	}
	if err := json.Unmarshal([]byte(line), &entry); err != nil {
		return nil
	}
	us, _ := strconv.ParseInt(entry.RealtimeTimestamp, 10, 64)
	ts := time.Unix(us/1_000_000, 0)

	// Priority: 0=emerg, 1=alert, 2=crit, 3=err, 4=warning
	prio, _ := strconv.Atoi(entry.Priority)
	level := "WARN"
	if prio <= 3 {
		level = "CRIT"
	}

	unit := entry.SystemdUnit
	if unit == "" {
		unit = entry.SyslogID
	}
	if unit == "" {
		unit = entry.Comm
	}

	msg := entry.Message
	if len(msg) > 140 {
		msg = msg[:140] + "…"
	}
	// Skip boring / noisy entries
	if isNoisyJournalEntry(unit, msg) {
		return nil
	}

	return &models.TimelineEvent{
		TimestampUnix: ts.Unix(),
		TimeStr:       ts.Format("15:04:05"),
		Source:        "journal",
		Level:         level,
		Unit:          stripServiceSuffix(unit),
		Message:       msg,
	}
}

// isNoisyJournalEntry returns true for entries that flood the timeline without adding value.
func isNoisyJournalEntry(unit, msg string) bool {
	noisy := []string{
		"setroubleshoot", "audit", "sudo", "sshd",
		"pam_unix", "AUDIT", "pam_unix(sudo",
	}
	for _, n := range noisy {
		if strings.Contains(unit, n) || strings.Contains(msg, n) {
			return true
		}
	}
	// libpod container exit events are captured via dsd docker — skip here
	if strings.HasPrefix(unit, "libpod-") || strings.HasPrefix(msg, "libpod-") {
		return true
	}
	return false
}

// deduplicateEvents collapses identical unit+level events within the same minute.
func deduplicateEvents(events []models.TimelineEvent) []models.TimelineEvent {
	type key struct {
		minuteUnix int64
		level      string
		unit       string
		msgPrefix  string // first 40 chars
	}
	seen := make(map[key]*models.TimelineEvent)
	var order []*models.TimelineEvent

	for i := range events {
		e := &events[i]
		prefix := e.Message
		if len(prefix) > 40 {
			prefix = prefix[:40]
		}
		k := key{
			minuteUnix: e.TimestampUnix / 60,
			level:      e.Level,
			unit:       e.Unit,
			msgPrefix:  prefix,
		}
		if existing, ok := seen[k]; ok {
			existing.Count++
		} else {
			e.Count = 1
			seen[k] = e
			order = append(order, e)
		}
	}

	result := make([]models.TimelineEvent, len(order))
	for i, e := range order {
		result[i] = *e
	}
	return result
}

// stripServiceSuffix shortens "k3s.service" → "k3s".
func stripServiceSuffix(s string) string {
	for _, sfx := range []string{".service", ".scope", ".slice"} {
		s = strings.TrimSuffix(s, sfx)
	}
	return s
}

// ── dmesg events ──────────────────────────────────────────────────────────────

// collectDmesgEvents reads kernel ring buffer entries since 'since'.
func collectDmesgEvents(ctx context.Context, since time.Time) ([]models.TimelineEvent, error) {
	dCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	cmd := localeSafeCmd(dCtx, "dmesg", "-T", "--level=err,warn,crit,emerg,alert") // #nosec G204
	out, err := cmd.Output()
	if err != nil {
		return nil, nil
	}

	var events []models.TimelineEvent
	for _, line := range strings.Split(strings.TrimSpace(string(out)), "\n") {
		ev := parseDmesgLine(line, since)
		if ev != nil {
			events = append(events, *ev)
		}
		if len(events) >= 500 {
			break
		}
	}
	return events, nil
}

// parseDmesgLine parses one dmesg -T line into a TimelineEvent.
// Format: "[Mon Jan 02 15:04:05 2006] message"
func parseDmesgLine(line string, since time.Time) *models.TimelineEvent {
	if !strings.HasPrefix(line, "[") {
		return nil
	}
	end := strings.Index(line, "]")
	if end < 0 {
		return nil
	}
	timeStr := strings.TrimSpace(line[1:end])
	msg := strings.TrimSpace(line[end+1:])

	// Parse timestamp: "Mon Jan  2 15:04:05 2026" (dmesg -T format)
	ts, err := time.Parse("Mon Jan  2 15:04:05 2006", timeStr)
	if err != nil {
		// Try two-digit day
		ts, err = time.Parse("Mon Jan 02 15:04:05 2006", timeStr)
		if err != nil {
			return nil
		}
	}
	if ts.Before(since) {
		return nil
	}

	level := "WARN"
	msgLower := strings.ToLower(msg)
	// "out of memory" catches the kernel OOM killer header ("Out of memory: Killed
	// process ..."), which does not contain the literal token "oom".
	if strings.Contains(msgLower, "error") || strings.Contains(msgLower, "fail") ||
		strings.Contains(msgLower, "oom") || strings.Contains(msgLower, "out of memory") ||
		strings.Contains(msgLower, "panic") || strings.Contains(msgLower, "oops") ||
		strings.Contains(msgLower, "bug:") {
		level = "CRIT"
	}

	// Extract subsystem from first word group in brackets: "[ 1234.567] EXT4-fs..."
	unit := extractKernelSubsystem(msg)

	if len(msg) > 140 {
		msg = msg[:140] + "…"
	}

	return &models.TimelineEvent{
		TimestampUnix: ts.Unix(),
		TimeStr:       ts.Format("15:04:05"),
		Source:        "dmesg",
		Level:         level,
		Unit:          unit,
		Message:       msg,
	}
}

// extractKernelSubsystem extracts the subsystem label from a kernel message.
// "EXT4-fs (sda1): warning..." → "EXT4-fs"
// "audit: type=1400..." → "audit"
func extractKernelSubsystem(msg string) string {
	// Common patterns: "SUBSYSTEM:", "SUBSYSTEM (device):", leading all-caps word
	if idx := strings.IndexAny(msg, ":("); idx > 0 && idx < 20 {
		candidate := strings.TrimSpace(msg[:idx])
		if candidate == strings.ToUpper(candidate) || strings.Contains(candidate, "-") {
			return candidate
		}
	}
	fields := strings.Fields(msg)
	if len(fields) > 0 {
		// Strip a trailing colon: a lowercase subsystem like "audit:" falls through
		// the all-caps/hyphen heuristic above to here, and Fields keeps the colon.
		if first := strings.TrimRight(fields[0], ":"); len(first) > 1 {
			return first
		}
	}
	return "kernel"
}

// ── load spikes ───────────────────────────────────────────────────────────────

// collectLoadSpikes reads current load average from /proc/loadavg and
// historical data from sar if available.
func collectLoadSpikes(ctx context.Context, since time.Time) []models.LoadSpike {
	// Always include current load
	var spikes []models.LoadSpike
	if cur := currentLoadSpike(); cur != nil {
		spikes = append(spikes, *cur)
	}

	// Try sar for historical load data
	sarSpikes := collectSarLoad(ctx, since)
	spikes = append(spikes, sarSpikes...)

	return spikes
}

// currentLoadSpike reads /proc/loadavg for the current reading.
func currentLoadSpike() *models.LoadSpike {
	data, err := os.ReadFile("/proc/loadavg") // #nosec G304
	if err != nil {
		return nil
	}
	fields := strings.Fields(string(data))
	if len(fields) < 3 {
		return nil
	}
	now := time.Now()
	l1, _ := strconv.ParseFloat(fields[0], 64)
	l5, _ := strconv.ParseFloat(fields[1], 64)
	l15, _ := strconv.ParseFloat(fields[2], 64)
	return &models.LoadSpike{
		TimestampUnix: now.Unix(),
		TimeStr:       now.Format("15:04:05") + " (now)",
		Load1:         l1,
		Load5:         l5,
		Load15:        l15,
	}
}

// collectSarLoad tries to get historical load data from sar.
// Returns empty if sar is not installed or has no data.
func collectSarLoad(ctx context.Context, since time.Time) []models.LoadSpike {
	sCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	// sar -q gives queue length and load average
	cmd := localeSafeCmd(sCtx, "sar", "-q", "-s", // #nosec G204
		since.Format("15:04:00"))
	out, err := cmd.Output()
	if err != nil {
		return nil
	}
	var spikes []models.LoadSpike
	today := time.Now().Format("2006-01-02")
	for _, line := range strings.Split(string(out), "\n") {
		s := parseSarLoadLine(line, today)
		if s != nil {
			spikes = append(spikes, *s)
		}
	}
	return spikes
}

// parseSarLoadLine parses one sar -q output line.
// Format: "HH:MM:SS  runq-sz  plist-sz  ldavg-1  ldavg-5  ldavg-15  blocked"
func parseSarLoadLine(line, today string) *models.LoadSpike {
	fields := strings.Fields(line)
	// Need at least 6 fields; first field is time HH:MM:SS
	if len(fields) < 6 {
		return nil
	}
	if _, err := time.Parse("15:04:05", fields[0]); err != nil {
		return nil
	}
	l1, err1 := strconv.ParseFloat(fields[3], 64)
	l5, err5 := strconv.ParseFloat(fields[4], 64)
	l15, err15 := strconv.ParseFloat(fields[5], 64)
	if err1 != nil || err5 != nil || err15 != nil {
		return nil
	}
	ts, _ := time.Parse("2006-01-02 15:04:05", today+" "+fields[0])
	return &models.LoadSpike{
		TimestampUnix: ts.Unix(),
		TimeStr:       fields[0],
		Load1:         l1,
		Load5:         l5,
		Load15:        l15,
	}
}

// ── filtering ─────────────────────────────────────────────────────────────────

// filterTopEvents keeps CRIT events plus a sample of WARN/INFO to stay under cap.
// Prioritises CRIT, then most recent WARN entries.
func filterTopEvents(events []models.TimelineEvent, cap int) []models.TimelineEvent {
	var crits, warns []models.TimelineEvent
	for _, e := range events {
		if e.Level == "CRIT" {
			crits = append(crits, e)
		} else {
			warns = append(warns, e)
		}
	}
	result := crits
	remaining := cap - len(crits)
	if remaining > 0 && len(warns) > 0 {
		// Take most recent WARNs
		start := len(warns) - remaining
		if start < 0 {
			start = 0
		}
		result = append(result, warns[start:]...)
	}
	sort.Slice(result, func(i, j int) bool {
		return result[i].TimestampUnix < result[j].TimestampUnix
	})
	return result
}

// runCmdTimeout is defined in run_cmd.go — used here for getsebool compatibility.
var _ = fmt.Sprintf // ensure fmt is used
