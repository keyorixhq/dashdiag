//go:build darwin

package collectors

import (
	"bufio"
	"context"
	"strconv"
	"strings"
	"time"

	"github.com/keyorixhq/dashdiag/internal/models"
)

// LaunchdCollector reads macOS service state from launchctl.
// Equivalent of the systemd collector on Linux.
type LaunchdCollector struct{}

func NewLaunchdCollector() *LaunchdCollector       { return &LaunchdCollector{} }
func (c *LaunchdCollector) Name() string           { return "Launchd" }
func (c *LaunchdCollector) Timeout() time.Duration { return 5 * time.Second }

func (c *LaunchdCollector) Collect(ctx context.Context) (interface{}, error) {
	info := &models.LaunchdInfo{}

	// launchctl list — prints all loaded services:
	// PID   Status  Label
	// 1234  -       com.apple.Spotlight
	// -     0       com.apple.screensaver
	// -     1       com.example.myapp   ← failed (non-zero exit, no PID)
	out, err := runCmd(ctx, "launchctl", "list")
	if err != nil {
		return info, nil
	}

	info.Total, info.Running, info.Failed = parseLaunchctlList(out)
	return info, nil
}

// parseLaunchctlList parses `launchctl list` output and returns total, running, failed.
func parseLaunchctlList(out string) (total, running int, failed []models.LaunchdService) {
	scanner := bufio.NewScanner(strings.NewReader(out))
	for scanner.Scan() {
		line := scanner.Text()
		// Skip header line
		if strings.HasPrefix(line, "PID") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 3 {
			continue
		}
		total++

		pidStr := fields[0]
		statusStr := fields[1]
		label := fields[2]

		// Skip Apple internal kernel/OS noise
		if isLaunchdNoise(label) {
			total--
			continue
		}

		pid := 0
		if pidStr != "-" {
			pid, _ = strconv.Atoi(pidStr)
		}
		if pid > 0 {
			running++
		}

		status := 0
		if statusStr != "-" {
			status, _ = strconv.Atoi(statusStr)
		}

		// Failed = not running + non-zero last exit code
		if pid == 0 && status != 0 {
			failed = append(failed, models.LaunchdService{
				Label:  label,
				Status: status,
			})
		}
	}
	return total, running, failed
}

// isLaunchdNoise filters out low-signal kernel/OS services that
// are never meaningful to report as failed.
func isLaunchdNoise(label string) bool {
	noisePrefixes := []string{
		"com.apple.security",
		"com.apple.xpc",
		"com.apple.launchd",
		"com.apple.private",
		"com.apple.system",
		"com.apple.WindowServer",
		"com.apple.CoreBrightness",
		"com.apple.audio",
		"com.apple.hiservices",
		"com.apple.ATS",
	}
	lower := strings.ToLower(label)
	for _, prefix := range noisePrefixes {
		if strings.HasPrefix(lower, strings.ToLower(prefix)) {
			return true
		}
	}
	return false
}
