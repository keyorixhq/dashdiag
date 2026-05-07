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
)

type ClockCollector struct{}

func NewClockCollector() *ClockCollector { return &ClockCollector{} }

func (c *ClockCollector) Name() string           { return "Clock" }
func (c *ClockCollector) Timeout() time.Duration { return 2 * time.Second }

// parseTimedatectl parses `timedatectl show` output (KEY=VALUE pairs).
func parseTimedatectl(r io.Reader) (synced bool, offsetMs float64, err error) {
	scanner := bufio.NewScanner(r)
	for scanner.Scan() {
		kv := strings.SplitN(scanner.Text(), "=", 2)
		if len(kv) != 2 {
			continue
		}
		switch kv[0] {
		case "NTPSynchronized":
			synced = kv[1] == "yes"
		case "NTPOffsetUsec":
			v, e := strconv.ParseFloat(kv[1], 64)
			if e != nil {
				return false, 0, fmt.Errorf("parsing NTPOffsetUsec: %w", e)
			}
			offsetMs = v / 1000.0
		}
	}
	return synced, offsetMs, scanner.Err()
}

// parseChronyTracking parses `chronyc tracking` output and returns offset in ms.
func parseChronyTracking(r io.Reader) (float64, error) {
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
			return 0, fmt.Errorf("parsing chrony offset: %w", err)
		}
		return v * 1000, nil
	}
	return 0, fmt.Errorf("system time offset not found in chrony output")
}

func (c *ClockCollector) Collect(ctx context.Context) (interface{}, error) {
	if runtime.GOOS == "darwin" {
		return c.collectDarwin(ctx)
	}
	return c.collectLinux(ctx)
}

func (c *ClockCollector) collectLinux(ctx context.Context) (*models.ClockInfo, error) {
	out, err := exec.CommandContext(ctx, "timedatectl", "show",
		"--property=NTPSynchronized,NTPOffsetUsec").Output()
	if err == nil {
		synced, offsetMs, parseErr := parseTimedatectl(strings.NewReader(string(out)))
		if parseErr == nil {
			return &models.ClockInfo{
				Synced:   synced,
				OffsetMs: offsetMs,
				Source:   "timedatectl",
			}, nil
		}
	}

	// Fallback: chronyc tracking
	out2, err2 := exec.CommandContext(ctx, "chronyc", "tracking").Output()
	if err2 != nil {
		return &models.ClockInfo{OffsetMs: -1, Source: "unavailable"}, nil
	}
	offsetMs, parseErr := parseChronyTracking(strings.NewReader(string(out2)))
	if parseErr != nil {
		return &models.ClockInfo{OffsetMs: -1, Source: "chronyc"}, nil
	}
	return &models.ClockInfo{
		Synced:   true,
		OffsetMs: offsetMs,
		Source:   "chronyc",
	}, nil
}

func (c *ClockCollector) collectDarwin(ctx context.Context) (*models.ClockInfo, error) {
	out, err := exec.CommandContext(ctx, "systemsetup", "-getusingnetworktime").Output()
	synced := false
	if err == nil {
		synced = strings.Contains(string(out), "Network Time: On")
	}
	return &models.ClockInfo{
		Synced:   synced,
		OffsetMs: -1,
		Source:   "systemsetup",
	}, nil
}
