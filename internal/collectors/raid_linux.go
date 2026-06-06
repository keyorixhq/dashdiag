//go:build linux

package collectors

import (
	"bufio"
	"context"
	"io"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/keyorixhq/dashdiag/internal/models"
)

// IsRAIDPresent returns true when mdadm arrays exist on this host.
// /proc/mdstat always exists on Linux, but only contains array entries
// when md devices are configured. We check for any "md" device line.
func IsRAIDPresent() bool {
	data, err := os.ReadFile("/proc/mdstat")
	if err != nil {
		return false
	}
	for _, line := range strings.Split(string(data), "\n") {
		// Array lines start with "md" followed by a digit or name
		if strings.HasPrefix(line, "md") && strings.Contains(line, ":") {
			return true
		}
	}
	return false
}

// RAIDCollector reads /proc/mdstat to detect degraded or failed mdadm arrays.
// Pure file read — no external commands, no root required.
type RAIDCollector struct{}

func NewRAIDCollector() *RAIDCollector { return &RAIDCollector{} }

func (c *RAIDCollector) Name() string           { return "RAID" }
func (c *RAIDCollector) Timeout() time.Duration { return 2 * time.Second }

func (c *RAIDCollector) Collect(_ context.Context) (interface{}, error) {
	f, err := os.Open("/proc/mdstat")
	if err != nil {
		// mdstat not present — no RAID configured, silent OK
		return &models.RAIDInfo{}, nil
	}
	defer f.Close() //nolint:errcheck
	return parseMDStat(f), nil
}

// parseMDStat parses /proc/mdstat content into RAID device states.
func parseMDStat(r io.Reader) *models.RAIDInfo {
	info := &models.RAIDInfo{}
	var current *models.RAIDDevice
	scanner := bufio.NewScanner(r)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())

		if line == "" || line == "Personalities :" || strings.HasPrefix(line, "unused") {
			if current != nil {
				info.Arrays = append(info.Arrays, *current)
				current = nil
			}
			continue
		}

		// Array header: "md0 : active raid1 sda1[0] sdb1[1]"
		if strings.Contains(line, ": active") || strings.Contains(line, ": inactive") {
			if current != nil {
				info.Arrays = append(info.Arrays, *current)
			}
			current = parseMDStatHeader(line)
			continue
		}
		if current == nil {
			continue
		}

		// Block-counts line carries the authoritative health: "[total/active] [U_]"
		// e.g. "976630464 blocks super 1.2 [2/1] [U_]". This is the ONLY reliable
		// degraded signal when a failed disk has fully dropped out of the array —
		// then it never appears as "(F)" in the header and active<total there is
		// false, so the array would otherwise read as healthy while running with
		// no redundancy. Use [n/m] as the authoritative active/total count.
		if total, active, ok := parseMDArrayCounts(line); ok {
			current.Total = total
			current.Active = active
			if active < total && current.State != "failed" {
				current.State = "degraded"
			}
		}

		// A rebuild in progress overrides degraded with the more useful state.
		if strings.Contains(line, "recovery") || strings.Contains(line, "resync") {
			if pct := parseRecoveryPct(line); pct > 0 {
				current.RebuildPct = pct
				current.State = "recovering"
			}
		}
	}
	if current != nil {
		info.Arrays = append(info.Arrays, *current)
	}
	return info
}

// parseMDArrayCounts extracts [total/active] from an mdstat block line such as
// "976630464 blocks super 1.2 [2/1] [U_]" — scanning bracket groups for the one
// containing "n/m" (the [U_] and [===>...] groups are skipped). ok=false if absent.
func parseMDArrayCounts(line string) (total, active int, ok bool) {
	for {
		open := strings.IndexByte(line, '[')
		if open < 0 {
			return 0, 0, false
		}
		end := strings.IndexByte(line[open:], ']')
		if end < 0 {
			return 0, 0, false
		}
		inner := line[open+1 : open+end]
		line = line[open+end+1:]
		slash := strings.IndexByte(inner, '/')
		if slash < 0 {
			continue // not the [n/m] group (e.g. [U_] or progress bar)
		}
		t, err1 := strconv.Atoi(strings.TrimSpace(inner[:slash]))
		a, err2 := strconv.Atoi(strings.TrimSpace(inner[slash+1:]))
		if err1 == nil && err2 == nil {
			return t, a, true
		}
	}
}

// parseMDStatHeader parses a /proc/mdstat header line like:
// "md0 : active raid1 sda1[0] sdb1[1](F) sdc1[2](S)"
func parseMDStatHeader(line string) *models.RAIDDevice {
	dev := &models.RAIDDevice{State: "active"}
	parts := strings.Fields(line)
	if len(parts) < 4 {
		return dev
	}

	dev.Name = parts[0]
	// parts[1] == ":"
	// parts[2] == "active" or "inactive"
	if parts[2] == "inactive" {
		dev.State = "failed"
	}
	dev.Level = parts[3]

	// Parse drive list: sda1[0], sdb1[1](F), sdc1[2](S)
	for _, p := range parts[4:] {
		if !strings.Contains(p, "[") {
			continue
		}
		dev.Total++
		lower := strings.ToLower(p)
		driveName := p[:strings.Index(p, "[")]
		if strings.Contains(lower, "(f)") {
			dev.Failed = append(dev.Failed, driveName)
		} else if strings.Contains(lower, "(s)") {
			dev.Spare = append(dev.Spare, driveName)
		} else {
			dev.Active++
		}
	}

	if len(dev.Failed) > 0 || dev.Active < dev.Total-len(dev.Spare) {
		dev.State = "degraded"
	}

	return dev
}

// parseRecoveryPct extracts the recovery percentage from a line like:
// "      [>...................]  recovery =  1.7% (...)"
func parseRecoveryPct(line string) float64 {
	idx := strings.Index(line, "=")
	if idx < 0 {
		return 0
	}
	rest := strings.TrimSpace(line[idx+1:])
	pctIdx := strings.Index(rest, "%")
	if pctIdx <= 0 {
		return 0
	}
	numStr := strings.TrimSpace(rest[:pctIdx])
	// may have leading spaces or range like "  1.7"
	fields := strings.Fields(numStr)
	if len(fields) == 0 {
		return 0
	}
	pct, _ := strconv.ParseFloat(fields[len(fields)-1], 64)
	return pct
}
