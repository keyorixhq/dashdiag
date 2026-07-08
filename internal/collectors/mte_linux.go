//go:build linux

package collectors

import (
	"bufio"
	"context"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"time"

	"github.com/keyorixhq/dashdiag/internal/models"
)

// MTECollector checks ARM Memory Tagging Extension (MTE) hardware/kernel
// support, whether the kernel is configured to log a tag-check-fault crash
// (debug.exception-trace), and parses any recent tag-check faults from the
// kernel journal.
type MTECollector struct{}

func NewMTECollector() *MTECollector           { return &MTECollector{} }
func (c *MTECollector) Name() string           { return "MTE" }
func (c *MTECollector) Timeout() time.Duration { return 5 * time.Second }

// IsMTEAvailable reports whether this host is arm64 with MTE hardware/kernel
// support (the "mte" flag in /proc/cpuinfo Features — the kernel only exposes
// it when both the CPU and CONFIG_ARM64_MTE agree, so presence is sufficient;
// no separate kernel-config check is needed).
func IsMTEAvailable() bool {
	if runtime.GOARCH != "arm64" {
		return false
	}
	data, err := readFile("/proc/cpuinfo")
	if err != nil {
		return false
	}
	cpu := parseProcCPUInfo(string(data))
	return hasFeature(cpu.features, "mte")
}

// mteFaultRe matches the kernel's tag-check-fault oops line, e.g.:
// "mte_test[2263]: unhandled exception: DABT (lower EL), ESR 0x0000000092000051, synchronous tag check fault in mte_test[b847a9c80000+1000]"
//
// The `.*?` between the prefix and the alternation must be non-greedy: a
// greedy `.*` walks to the end of the line and backtracks minimally, which
// finds "synchronous" matching as a SUFFIX of "asynchronous" first (since
// that's the rightmost/latest position satisfying the rest of the pattern),
// misclassifying every async fault as sync. Non-greedy finds the correct,
// earliest (and only real) occurrence instead.
var mteFaultRe = regexp.MustCompile(`(\S+)\[(\d+)\]: unhandled exception:.*?(synchronous|asynchronous) tag check fault`)

func (c *MTECollector) Collect(ctx context.Context) (interface{}, error) {
	info := &models.MTEInfo{Available: true}

	exceptionTrace, err := readIntFile("/proc/sys/debug/exception-trace")
	if err != nil {
		info.StatusReason = "debug.exception-trace unreadable: " + err.Error()
		return info, nil
	}
	info.ExceptionTraceEnabled = exceptionTrace == 1
	if !info.ExceptionTraceEnabled {
		// Nothing more to check — a tag-check fault leaves no kernel-log trace
		// while this sysctl is off, so scanning the log would be pointless.
		return info, nil
	}

	// Same journalctl -> dmesg(iso) -> dmesg fallback chain as OOMCollector —
	// proven to handle non-systemd hosts and busybox dmesg (Alpine).
	usedDmesg := false
	out, err := runCmd(ctx, "journalctl", "-k", "--since", "24 hours ago",
		"--no-pager", "-o", "short-iso", "--grep", "tag check fault")
	if err != nil {
		out, err = runCmd(ctx, "dmesg", "--time-format", "iso")
		if err != nil {
			out, err = runCmd(ctx, "dmesg")
		}
		if err != nil {
			info.StatusReason = "kernel log unreadable (journalctl -k and dmesg both failed)"
			return info, nil
		}
		usedDmesg = true
	}

	events := parseMTEFaultEvents(out)
	if usedDmesg {
		events = filterMTEFaultsRecent(events, time.Now().Add(-24*time.Hour))
	}
	info.RecentFaults = events
	return info, nil
}

// mteTimestampLayouts mirrors oomTimestampLayouts — journalctl short-iso.
var mteTimestampLayouts = []string{
	"2006-01-02T15:04:05-0700",
	"2006-01-02T15:04:05Z",
}

// parseMTETimestamp extracts a timestamp from the first field of a
// journalctl short-iso line. Returns zero time on failure.
func parseMTETimestamp(line string) time.Time {
	if len(line) < 19 {
		return time.Time{}
	}
	end := strings.IndexByte(line, ' ')
	if end < 0 {
		end = len(line)
	}
	token := line[:end]
	for _, layout := range mteTimestampLayouts {
		if len(token) != len(layout) {
			continue
		}
		if ts, err := time.Parse(layout, token); err == nil {
			return ts
		}
	}
	return time.Time{}
}

// filterMTEFaultsRecent keeps events at or after cutoff. Events with a zero
// timestamp (undated, e.g. boot-relative dmesg) are kept conservatively — a
// real fault is never dropped just because its time couldn't be parsed.
func filterMTEFaultsRecent(events []models.MTEFaultEvent, cutoff time.Time) []models.MTEFaultEvent {
	kept := events[:0]
	for _, e := range events {
		if e.Timestamp.IsZero() || e.Timestamp.After(cutoff) {
			kept = append(kept, e)
		}
	}
	return kept
}

func parseMTEFaultEvents(out string) []models.MTEFaultEvent {
	var events []models.MTEFaultEvent
	seen := map[string]bool{} // dedup by pid+process+fault-type
	scanner := bufio.NewScanner(strings.NewReader(out))
	for scanner.Scan() {
		line := scanner.Text()
		m := mteFaultRe.FindStringSubmatch(line)
		if m == nil {
			continue
		}
		pid, _ := strconv.Atoi(m[2])
		ev := models.MTEFaultEvent{
			Process:   m[1],
			PID:       pid,
			FaultType: m[3],
			Timestamp: parseMTETimestamp(line),
		}
		key := strconv.Itoa(ev.PID) + ev.Process + ev.FaultType
		if seen[key] {
			continue
		}
		seen[key] = true
		events = append(events, ev)
	}
	return events
}
