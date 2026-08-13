//go:build linux

package collectors

import (
	"bufio"
	"context"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/keyorixhq/dashdiag/internal/models"
)

// OOMCollector parses OOM killer events from the kernel journal.
type OOMCollector struct{}

func NewOOMCollector() *OOMCollector           { return &OOMCollector{} }
func (c *OOMCollector) Name() string           { return "OOM" }
func (c *OOMCollector) Timeout() time.Duration { return 5 * time.Second }

var (
	// "Out of memory: Kill process 12345 (nginx) score 900 or sacrifice child"
	oomKillRe = regexp.MustCompile(`Out of memory.*Kill process (\d+) \(([^)]+)\)`)
	// "Killed process 12345 (nginx) total-vm:..."
	oomKilledRe = regexp.MustCompile(`Killed process (\d+) \(([^)]+)\)`)
)

func (c *OOMCollector) Collect(ctx context.Context) (interface{}, error) {
	info := &models.OOMInfo{Available: true}

	// Use journalctl to search kernel messages for OOM events.
	// --since "24 hours ago" scopes to recent events.
	// -k limits to kernel messages (same as dmesg but with timestamps).
	usedDmesg := false
	out, err := runCmd(ctx, "journalctl", "-k", "--since", "24 hours ago",
		"--no-pager", "-o", "short-iso", "--grep", "Out of memory|Killed process")
	if err != nil {
		// journalctl not available — try dmesg fallback (util-linux: ISO timestamps).
		out, err = runCmd(ctx, "dmesg", "--time-format", "iso")
		if err != nil {
			// busybox dmesg (Alpine and other non-systemd hosts) doesn't support
			// --time-format, so the call above errors even though `dmesg` itself works
			// fine as root. Retry plain dmesg — its boot-relative timestamps are handled
			// conservatively by filterOOMRecent below. Without this, OOM detection was
			// DEAD on Alpine even as root (found on an Alpine 3.22 EC2 box): the section
			// read "not verified" though dmesg was fully readable.
			out, err = runCmd(ctx, "dmesg")
		}
		if err != nil {
			// Neither journalctl nor dmesg is readable (e.g. non-systemd host with
			// kernel.dmesg_restrict=1 and no root) — we could NOT check for OOM kills.
			// Keep the section but flag it unverified, so the verdict says "not
			// checked" rather than a silent verified "0 OOM kills" (false-OK).
			info.StatusReason = "kernel log unreadable (journalctl -k and dmesg both failed)"
			return info, nil
		}
		usedDmesg = true
	}

	events, truncated := parseOOMEvents(out)
	info.EventsCountUnverified = truncated
	if usedDmesg {
		// dmesg has no `--since`; the kernel ring buffer can hold OOM lines from days
		// ago on a long-running host. Counting them all as "last 24h" produced a CRIT
		// for an OOM that happened long ago (recency-gate). Drop dated events older
		// than 24h; keep undated ones (boot-relative timestamps when `--time-format
		// iso` is unsupported) conservatively rather than silently dropping a real OOM.
		events = filterOOMRecent(events, time.Now().Add(-24*time.Hour))
	}
	info.EventsLast24h = len(events)
	if len(events) > 5 {
		info.RecentEvents = events[len(events)-5:]
	} else {
		info.RecentEvents = events
	}
	return info, nil
}

// oomTimestampLayouts covers journalctl short-iso ("2006-01-02T15:04:05+0700")
// and the rare short-iso-precise variant that includes fractional seconds.
var oomTimestampLayouts = []string{
	"2006-01-02T15:04:05-0700",
	"2006-01-02T15:04:05Z",
}

// parseOOMTimestamp tries to extract a timestamp from the first field of a
// journalctl short-iso line.  Returns zero time on failure (graceful degradation:
// the rule engine falls back to co-occurrence detection when timestamps are absent).
func parseOOMTimestamp(line string) time.Time {
	if len(line) < 19 {
		return time.Time{}
	}
	// First whitespace-delimited token is the timestamp
	end := strings.IndexByte(line, ' ')
	if end < 0 {
		end = len(line)
	}
	token := line[:end]
	for _, layout := range oomTimestampLayouts {
		if len(token) != len(layout) {
			continue
		}
		if ts, err := time.Parse(layout, token); err == nil {
			return ts
		}
	}
	return time.Time{}
}

// filterOOMRecent keeps OOM events that occurred at or after cutoff. Events with a
// zero timestamp (couldn't be dated — e.g. boot-relative dmesg) are kept, so a real
// OOM is never dropped just because we couldn't parse its time.
func filterOOMRecent(events []models.OOMEvent, cutoff time.Time) []models.OOMEvent {
	kept := events[:0]
	for _, e := range events {
		if e.Timestamp.IsZero() || e.Timestamp.After(cutoff) {
			kept = append(kept, e)
		}
	}
	return kept
}

// parseOOMEvents scans out for OOM-kill lines. The second return is true when
// bufio.Scanner stopped early on a scan error (e.g. bufio.ErrTooLong from a
// line past its ~64KB default buffer) — any OOM events on lines after that
// point are silently missing, so the caller must disclose the count as
// possibly incomplete rather than a verified total (internal-collectors-25-05).
func parseOOMEvents(out string) ([]models.OOMEvent, bool) {
	var events []models.OOMEvent
	seen := map[string]bool{} // deduplicate by pid+process
	scanner := bufio.NewScanner(strings.NewReader(out))
	for scanner.Scan() {
		line := scanner.Text()
		ev := models.OOMEvent{Timestamp: parseOOMTimestamp(line)}

		if m := oomKillRe.FindStringSubmatch(line); len(m) == 3 {
			pid, _ := strconv.Atoi(m[1])
			ev.PID = pid
			ev.Process = m[2]
		} else if m := oomKilledRe.FindStringSubmatch(line); len(m) == 3 { // NOSONAR — same extraction as oomKillRe branch; two OOM message formats, identical fields
			pid, _ := strconv.Atoi(m[1])
			ev.PID = pid
			ev.Process = m[2]
		} else {
			continue
		}

		key := strconv.Itoa(ev.PID) + ev.Process
		if seen[key] {
			continue
		}
		seen[key] = true
		events = append(events, ev)
	}
	return events, scanner.Err() != nil
}
