//go:build linux

package collectors

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/keyorixhq/dashdiag/internal/models"
)

// CronCollector inspects cron daemon health, job failure history,
// crontab quality issues, and anacron staleness.
// Linux-only (systemd, journald, /var/spool/anacron paths).
type CronCollector struct{}

func NewCronCollector() *CronCollector { return &CronCollector{} }

func (c *CronCollector) Name() string           { return "Cron" }
func (c *CronCollector) Timeout() time.Duration { return 10 * time.Second }

func (c *CronCollector) Collect(ctx context.Context) (interface{}, error) {
	info := &models.CronInfo{}

	// 1. Daemon detection
	detectCronDaemon(ctx, info)

	// 2. Crontab quality scan
	info.QualityIssues = scanCrontabQuality()

	// 3. Recent failures from journal/syslog
	info.Failures = scanCronFailures(ctx)

	// 4. Anacron staleness
	if info.AnacronPresent {
		info.AnacronJobs = checkAnacronStaleness()
	}

	// 5. Systemd timers (fallback info when no cron daemon)
	if !info.DaemonActive {
		info.SystemdTimers = countSystemdTimers(ctx)
	}

	return info, nil
}

// ── daemon detection ──────────────────────────────────────────────────────────

func detectCronDaemon(ctx context.Context, info *models.CronInfo) {
	daemons := []string{"crond", "cron", "fcron"}
	for _, d := range daemons {
		out, err := runCmd(ctx, "systemctl", "is-active", d)
		if err == nil && strings.TrimSpace(out) == "active" {
			info.DaemonActive = true
			info.DaemonName = d
			break
		}
	}
	// Anacron: present if binary exists (doesn't run as a persistent daemon)
	if _, err := os.Stat("/usr/sbin/anacron"); err == nil {
		info.AnacronPresent = true
	} else if _, err := os.Stat("/usr/bin/anacron"); err == nil {
		info.AnacronPresent = true
	}
}

// ── crontab quality ───────────────────────────────────────────────────────────

var cronDirs = []string{
	"/etc/cron.d",
	"/etc/cron.daily",
	"/etc/cron.weekly",
	"/etc/cron.monthly",
	"/etc/cron.hourly",
}

func scanCrontabQuality() []models.CronJob {
	var issues []models.CronJob

	// System crontabs in /etc/cron.d and /etc/cron.*/
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
			jobs := parseCrontabFile(path, path)
			issues = append(issues, jobs...)
		}
	}

	// Root crontab
	issues = append(issues, parseCrontabFile("/var/spool/cron/crontabs/root", "user:root")...)

	// User crontabs
	userEntries, _ := os.ReadDir("/var/spool/cron/crontabs")
	for _, e := range userEntries {
		if e.IsDir() || e.Name() == "root" {
			continue
		}
		path := filepath.Join("/var/spool/cron/crontabs", e.Name())
		issues = append(issues, parseCrontabFile(path, "user:"+e.Name())...)
	}

	return issues
}

// parseCrontabFile reads a crontab file and checks each job line for quality issues.
// Returns at most one CronJob entry per file (deduplicating issues across lines).
func parseCrontabFile(path, source string) []models.CronJob {
	data, err := os.ReadFile(filepath.Clean(path)) // #nosec G304 -- known cron paths
	if err != nil {
		return nil
	}

	// System crontabs in /etc/cron.{hourly,daily,weekly,monthly}/ are run-parts
	// scripts — they intentionally have no MAILTO or PATH header. Skip MAILTO
	// check for these; only check /etc/cron.d/* and user crontabs.
	isRunParts := strings.Contains(path, "/cron.hourly/") ||
		strings.Contains(path, "/cron.daily/") ||
		strings.Contains(path, "/cron.weekly/") ||
		strings.Contains(path, "/cron.monthly/")

	var hasPath, hasMailto bool
	for _, line := range strings.Split(string(data), "\n") {
		upper := strings.ToUpper(strings.TrimSpace(line))
		if strings.HasPrefix(upper, "PATH=") {
			hasPath = true
		}
		if strings.HasPrefix(upper, "MAILTO=") {
			hasMailto = true
		}
	}

	// Collect unique issues across all lines in this file
	issueSet := map[string]bool{}
	var missingCmd string

	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if strings.Contains(line, "=") && !strings.ContainsAny(line, " \t") {
			continue // variable assignment
		}

		// User crontabs (source "user:NAME") have no username column; system
		// crontabs (/etc/cron.d, source = file path) put the user before the cmd.
		hasUserField := !strings.HasPrefix(source, "user:")
		cmd := extractCronCommand(line, hasUserField)
		if cmd == "" {
			continue
		}

		// Relative path without PATH set (only flag once per file)
		if !hasPath && !strings.HasPrefix(cmd, "/") {
			issueSet["no PATH set and command uses relative path — may fail silently"] = true
		}

		// Missing binary (only report first missing binary found).
		// binary is parsed from crontab content (taint source). We only stat
		// absolute, lexically-clean paths under known system roots — never a
		// caller-influenced relative or traversing path. The stat only checks
		// existence (no open/exec), but the guard keeps the taint flow closed.
		if missingCmd == "" && strings.HasPrefix(cmd, "/") {
			binary := strings.Fields(cmd)[0]
			if isStattableBinaryPath(binary) {
				if _, err := os.Stat(binary); os.IsNotExist(err) { // #nosec G703 -- path guarded by isStattableBinaryPath (absolute, cleaned, no traversal)
					missingCmd = "command not found: " + binary
				}
			}
		}
	}

	// MAILTO check — only for /etc/cron.d/ and user crontabs, not run-parts dirs
	if !isRunParts && !hasMailto {
		issueSet["no MAILTO set — errors go to local mailbox unread"] = true
	}

	if missingCmd != "" {
		issueSet[missingCmd] = true
	}

	if len(issueSet) == 0 {
		return nil
	}

	var issues []string
	for issue := range issueSet {
		issues = append(issues, issue)
	}

	return []models.CronJob{{
		Source: source,
		Line:   "",
		Issues: issues,
	}}
}

// extractCronCommand returns the command portion of a crontab line.
// hasUserField selects the layout: system crontabs (/etc/cron.d) are
// "min hour dom mon dow user cmd" (6 leading fields); user crontabs are
// "min hour dom mon dow cmd" (5). The caller knows which from the file source,
// so we don't guess from the line content — guessing dropped the first command
// token whenever it was a bare word (e.g. "backup --incremental ...").
func extractCronCommand(line string, hasUserField bool) string {
	fields := strings.Fields(line)
	// Standard crontab: 5 time fields + command
	if len(fields) < 6 {
		return ""
	}
	timeFields := 5
	if hasUserField {
		timeFields = 6
	}
	if len(fields) <= timeFields {
		return ""
	}
	return strings.Join(fields[timeFields:], " ")
}

// ── failure scanning ──────────────────────────────────────────────────────────

func scanCronFailures(ctx context.Context) []models.CronFailure {
	var failures []models.CronFailure

	// Try journalctl first (systemd systems)
	out, err := runCmd(ctx, "journalctl", "-u", "crond", "-u", "cron",
		"--since", "24 hours ago", "--no-pager", "-q", "--output=short")
	if err == nil {
		failures = append(failures, parseCronJournalFailures(out)...)
	}

	// Also check syslog-style files
	for _, logPath := range []string{"/var/log/cron", "/var/log/cron.log", "/var/log/syslog"} {
		data, err := os.ReadFile(filepath.Clean(logPath)) // #nosec G304 -- known log paths
		if err != nil {
			continue
		}
		failures = append(failures, parseCronLogFailures(string(data))...)
		break // Use first available file
	}

	return deduplicateCronFailures(failures)
}

// parseCronJournalFailures extracts FAILED/error lines from journalctl output.
func parseCronJournalFailures(out string) []models.CronFailure {
	var failures []models.CronFailure
	now := time.Now()
	for _, line := range strings.Split(out, "\n") {
		lower := strings.ToLower(line)
		if !strings.Contains(lower, "failed") && !strings.Contains(lower, "error") &&
			!strings.Contains(lower, "exit status") {
			continue
		}
		// Skip lines about the cron daemon itself starting/stopping
		if strings.Contains(lower, "started") || strings.Contains(lower, "stopping") {
			continue
		}
		ts, job := parseCronLogLine(line)
		agoMin := 0
		if !ts.IsZero() {
			agoMin = int(now.Sub(ts).Minutes())
		}
		if job != "" {
			failures = append(failures, models.CronFailure{
				Job:     job,
				Message: truncateCron(line, 120),
				AgoMin:  agoMin,
			})
		}
	}
	return failures
}

// parseCronLogFailures scans traditional /var/log/cron for failure lines.
func parseCronLogFailures(content string) []models.CronFailure {
	var failures []models.CronFailure
	cutoff := time.Now().Add(-24 * time.Hour)
	now := time.Now()

	for _, line := range strings.Split(content, "\n") {
		lower := strings.ToLower(line)
		if !strings.Contains(lower, "failed") && !strings.Contains(lower, "exit status") {
			continue
		}
		ts, job := parseCronLogLine(line)
		if ts.Before(cutoff) || ts.IsZero() {
			continue
		}
		if job == "" {
			continue
		}
		failures = append(failures, models.CronFailure{
			Job:     job,
			Message: truncateCron(line, 120),
			AgoMin:  int(now.Sub(ts).Minutes()),
		})
	}
	return failures
}

// parseCronLogLine extracts the timestamp and job name from a cron log line.
// Handles: "May 19 10:00:01 host crond[123]: (root) CMD (command)"
func parseCronLogLine(line string) (time.Time, string) {
	// Syslog prefix: "May 19 10:00:01 hostname"
	fields := strings.Fields(line)
	if len(fields) < 6 {
		return time.Time{}, ""
	}

	// Try to parse timestamp from first 3 fields: "May 19 10:00:01"
	tsStr := fmt.Sprintf("%d %s %s %s", time.Now().Year(), fields[0], fields[1], fields[2])
	ts, _ := time.Parse("2006 Jan 2 15:04:05", tsStr)

	// Extract job: look for CMD pattern "(user) CMD (command)"
	if idx := strings.Index(line, ") CMD ("); idx >= 0 {
		rest := line[idx+7:]
		if end := strings.LastIndex(rest, ")"); end > 0 {
			return ts, rest[:end]
		}
	}
	// Fallback: use the whole message part
	if len(fields) > 5 {
		return ts, strings.Join(fields[5:], " ")
	}
	return ts, ""
}

func deduplicateCronFailures(failures []models.CronFailure) []models.CronFailure {
	seen := map[string]bool{}
	var out []models.CronFailure
	for _, f := range failures {
		if !seen[f.Job] {
			seen[f.Job] = true
			out = append(out, f)
		}
	}
	return out
}

// ── anacron staleness ─────────────────────────────────────────────────────────

// checkAnacronStaleness reads /var/spool/anacron/cron.{daily,weekly,monthly}
// timestamps to detect jobs that haven't run on schedule.
// Anacron writes the last-run date (YYYYMMDD) to these files.
func checkAnacronStaleness() []models.AnacronJob {
	periods := []struct {
		name    string
		maxDays int
	}{
		{"daily", 2},    // overdue if >2 days
		{"weekly", 9},   // overdue if >9 days
		{"monthly", 35}, // overdue if >35 days
	}

	var jobs []models.AnacronJob
	for _, p := range periods {
		path := "/var/spool/anacron/cron." + p.name
		data, err := os.ReadFile(filepath.Clean(path)) // #nosec G304
		if err != nil {
			jobs = append(jobs, models.AnacronJob{Name: p.name, LastRunH: -1})
			continue
		}
		dateStr := strings.TrimSpace(string(data))
		t, err := time.Parse("20060102", dateStr)
		if err != nil {
			jobs = append(jobs, models.AnacronJob{Name: p.name, LastRunH: -1})
			continue
		}
		hoursAgo := int(time.Since(t).Hours())
		overdueH := 0
		if hoursAgo > p.maxDays*24 {
			overdueH = hoursAgo - p.maxDays*24
		}
		jobs = append(jobs, models.AnacronJob{
			Name:     p.name,
			LastRunH: hoursAgo,
			OverdueH: overdueH,
		})
	}
	return jobs
}

// ── systemd timers fallback ───────────────────────────────────────────────────

func countSystemdTimers(ctx context.Context) int {
	out, err := runCmd(ctx, "systemctl", "list-timers", "--no-legend", "--no-pager")
	if err != nil {
		return 0
	}
	count := 0
	for _, line := range strings.Split(out, "\n") {
		if strings.TrimSpace(line) != "" {
			count++
		}
	}
	return count
}

func truncateCron(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}

// isStattableBinaryPath reports whether p is safe to os.Stat as a cron command
// binary: it must be absolute and lexically clean (no ".." traversal). Cron
// command binaries are normally plain absolute paths like /usr/bin/foo; for
// anything else we decline to stat rather than follow a caller-influenced path
// parsed from crontab content. Guards gosec G703 (THREAT_MODEL_CLI.md
// path-traversal class, same as the SELinux F-2 fix).
func isStattableBinaryPath(p string) bool {
	if !strings.HasPrefix(p, "/") {
		return false
	}
	if strings.Contains(p, "..") {
		return false
	}
	return filepath.Clean(p) == p
}
