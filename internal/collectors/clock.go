package collectors

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"os/exec"
	"runtime"
	"strconv"
	"strings"
	"time"

	"github.com/keyorixhq/dashdiag/internal/models"
	"github.com/keyorixhq/dashdiag/internal/platform"
)

type ClockCollector struct{}

func NewClockCollector() *ClockCollector { return &ClockCollector{} }

func (c *ClockCollector) Name() string           { return "Clock" }
func (c *ClockCollector) Timeout() time.Duration { return 2 * time.Second }

func (c *ClockCollector) Collect(ctx context.Context) (interface{}, error) {
	info := &models.ClockInfo{}
	if runtime.GOOS == "darwin" {
		return c.collectDarwin(ctx, info)
	}
	return c.collectLinux(ctx, info)
}

func (c *ClockCollector) collectDarwin(ctx context.Context, info *models.ClockInfo) (interface{}, error) {
	// timed is the macOS clock synchronisation daemon. If it's running, the clock is synced.
	// systemsetup -getusingnetworktime requires sudo on macOS Ventura+ and is unreliable.
	info.OffsetMs = -1
	if err := exec.CommandContext(ctx, "pgrep", "timed").Run(); err == nil {
		info.Synced = true
		info.Source = "timed"
	} else {
		info.Synced = false
		info.Source = "unavailable"
	}
	return info, nil
}

func (c *ClockCollector) collectLinux(ctx context.Context, info *models.ClockInfo) (interface{}, error) {
	if platform.DetectContainerContext().InContainer {
		info.Synced = true
		info.Source = "host"
		info.OffsetMs = -1
		return info, nil
	}

	// Step 1: plain `timedatectl show` — no --property filter, works on all distro versions.
	// Using --property=NTPSynchronized,NTPOffsetUsec fails on Ubuntu 24.04 because
	// timedatectl treats the comma-separated string as a single unknown property name,
	// returning empty output and leaving info.Synced=false even though NTP is active.
	out, err := exec.CommandContext(ctx, "timedatectl", "show").Output()
	if err == nil {
		for _, line := range strings.Split(string(out), "\n") {
			if strings.HasPrefix(line, "NTPSynchronized=") {
				info.Synced = strings.TrimPrefix(line, "NTPSynchronized=") == "yes"
			}
			// Ubuntu 22.04 and earlier: NTPOffsetUsec present here.
			if strings.HasPrefix(line, "NTPOffsetUsec=") {
				val := strings.TrimPrefix(line, "NTPOffsetUsec=")
				if val != "" {
					if usec, parseErr := strconv.ParseFloat(val, 64); parseErr == nil {
						info.OffsetMs = usec / 1000.0
						info.Source = "timedatectl"
					}
				}
			}
		}
	}

	// Step 2: Ubuntu 24.04+ removed NTPOffsetUsec; offset lives in timesync-status.
	if info.Source == "" || info.OffsetMs == 0 {
		tsOut, tsErr := exec.CommandContext(ctx, "timedatectl", "timesync-status").Output()
		if tsErr == nil {
			if ms, parseErr := parseTimesyncStatus(strings.NewReader(string(tsOut))); parseErr == nil {
				info.OffsetMs = ms
				info.Source = "timedatectl-timesync"
			}
		}
	}

	// Step 3: chronyc fallback for RHEL, Rocky, Amazon Linux.
	if info.Source == "" {
		chrOut, chrErr := exec.CommandContext(ctx, "chronyc", "tracking").Output()
		if chrErr == nil {
			if synced, ms, parseErr := parseChronyTracking(strings.NewReader(string(chrOut))); parseErr == nil {
				info.Synced = synced
				info.OffsetMs = ms
				info.Source = "chronyc"
			}
		}
	}

	// Step 4: graceful degradation — never return nil, never return error.
	if info.Source == "" {
		info.Source = "unavailable"
		info.OffsetMs = -1
	}

	return info, nil
}

// parseTimesyncStatus parses `timedatectl timesync-status` and returns the offset in ms.
// It finds the first "Offset:" line, e.g. "       Offset: +1.866ms".
func parseTimesyncStatus(r io.Reader) (float64, error) {
	scanner := bufio.NewScanner(r)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if !strings.HasPrefix(line, "Offset:") {
			continue
		}
		val := strings.TrimSpace(strings.TrimPrefix(line, "Offset:"))
		return parseOffsetString(val)
	}
	return 0, fmt.Errorf("offset line not found")
}

// parseOffsetString converts "+1.866ms", "+123us", "+0.001s" to milliseconds.
func parseOffsetString(s string) (float64, error) {
	s = strings.TrimSpace(s)
	switch {
	case strings.HasSuffix(s, "ms"):
		f, err := strconv.ParseFloat(strings.TrimSuffix(s, "ms"), 64)
		return f, err
	case strings.HasSuffix(s, "us"):
		f, err := strconv.ParseFloat(strings.TrimSuffix(s, "us"), 64)
		return f / 1000.0, err
	case strings.HasSuffix(s, "s"):
		f, err := strconv.ParseFloat(strings.TrimSuffix(s, "s"), 64)
		return f * 1000.0, err
	default:
		return 0, fmt.Errorf("unknown offset format: %s", s)
	}
}

// parseChronyTracking parses `chronyc tracking` and returns synced + offset in ms.
func parseChronyTracking(r io.Reader) (bool, float64, error) {
	scanner := bufio.NewScanner(r)
	for scanner.Scan() {
		line := scanner.Text()
		if !strings.HasPrefix(line, "System time") {
			continue
		}
		parts := strings.SplitN(line, ":", 2)
		if len(parts) != 2 {
			continue
		}
		fields := strings.Fields(parts[1])
		if len(fields) == 0 {
			continue
		}
		v, err := strconv.ParseFloat(fields[0], 64)
		if err != nil {
			return false, 0, fmt.Errorf("parsing chrony offset: %w", err)
		}
		return true, v * 1000, nil
	}
	return false, 0, fmt.Errorf("system time offset not found in chrony output")
}
