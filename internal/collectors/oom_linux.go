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
	out, err := runCmd(ctx, "journalctl", "-k", "--since", "24 hours ago",
		"--no-pager", "-o", "short-iso", "--grep", "Out of memory|Killed process")
	if err != nil {
		// journalctl not available — try dmesg fallback
		out, err = runCmd(ctx, "dmesg", "--time-format", "iso")
		if err != nil {
			return info, nil
		}
	}

	events := parseOOMEvents(out)
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

func parseOOMEvents(out string) []models.OOMEvent {
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
		} else if m := oomKilledRe.FindStringSubmatch(line); len(m) == 3 {
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
	return events
}
