package drilldown

import (
	"context"
	"runtime"
	"strings"

	"github.com/keyorixhq/dashdiag/internal/models"
)

// ClockTracking returns detailed NTP synchronisation status.
func ClockTracking(ctx context.Context) (*models.Details, error) {
	if runtime.GOOS == "darwin" {
		return clockTrackingMac(ctx)
	}
	return clockTrackingLinux(ctx)
}

func clockTrackingLinux(ctx context.Context) (*models.Details, error) {
	out, err := runCmd(ctx, "chronyc", "tracking")
	if err != nil {
		// Try timedatectl as fallback
		out, err = runCmd(ctx, "timedatectl", "show")
		if err != nil {
			return nil, nil
		}
		return parseTimedatectl(out), nil
	}
	return parseChronyTracking(out), nil
}

func parseChronyTracking(out string) *models.Details {
	kv := make(map[string]string)
	for _, line := range strings.Split(out, "\n") {
		parts := strings.SplitN(line, ":", 2)
		if len(parts) != 2 {
			continue
		}
		key := strings.TrimSpace(parts[0])
		val := strings.TrimSpace(parts[1])
		if key != "" && val != "" {
			kv[key] = val
		}
	}
	return &models.Details{
		Type:  "kv_table",
		Title: "chronyc tracking",
		KV:    kv,
	}
}

func parseTimedatectl(out string) *models.Details {
	kv := make(map[string]string)
	for _, line := range strings.Split(out, "\n") {
		parts := strings.SplitN(line, "=", 2)
		if len(parts) != 2 {
			continue
		}
		kv[parts[0]] = parts[1]
	}
	return &models.Details{
		Type:  "kv_table",
		Title: "timedatectl status",
		KV:    kv,
	}
}

func clockTrackingMac(ctx context.Context) (*models.Details, error) {
	kv := make(map[string]string)

	// Check if timed is running
	out, err := runCmd(ctx, "pgrep", "timed")
	if err == nil && strings.TrimSpace(out) != "" {
		kv["timed_pid"] = strings.TrimSpace(out)
		kv["timed_running"] = "yes"
	} else {
		kv["timed_running"] = "no"
	}

	// sntp query (available without root on macOS)
	sntpOut, err2 := runCmd(ctx, "sntp", "-t", "1", "time.apple.com")
	if err2 == nil {
		for _, line := range strings.Split(sntpOut, "\n") {
			if strings.Contains(line, "offset") || strings.Contains(line, "stratum") {
				kv["sntp_result"] = strings.TrimSpace(line)
				break
			}
		}
	}

	return &models.Details{
		Type:  "kv_table",
		Title: "Network time status",
		KV:    kv,
	}, nil
}
