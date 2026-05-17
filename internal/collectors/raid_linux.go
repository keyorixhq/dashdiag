//go:build linux

package collectors

import (
	"bufio"
	"context"
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
	info := &models.RAIDInfo{}

	f, err := os.Open("/proc/mdstat")
	if err != nil {
		// mdstat not present — no RAID configured, silent OK
		return info, nil
	}
	defer f.Close() //nolint:errcheck

	var current *models.RAIDDevice
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := scanner.Text()
		line = strings.TrimSpace(line)

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

		// Block counts line — extract recovery percentage if present
		// "      [>...................]  recovery =  1.7% (..."
		if current != nil && strings.Contains(line, "recovery") {
			pct := parseRecoveryPct(line)
			if pct > 0 {
				current.RebuildPct = pct
				current.State = "recovering"
			}
		}
		if current != nil && strings.Contains(line, "resync") {
			pct := parseRecoveryPct(line)
			if pct > 0 {
				current.RebuildPct = pct
				current.State = "recovering"
			}
		}
	}
	if current != nil {
		info.Arrays = append(info.Arrays, *current)
	}

	return info, nil
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
