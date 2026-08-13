package drilldown

import (
	"context"
	"errors"
	"os"
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
			// Unlike systemd.go's "no journald on this host" nil,nil (a genuine
			// not-applicable case), a Clock WARN/CRIT fired because SOMETHING
			// looked wrong with time sync — both probes failing here is a real
			// gap in the supporting detail, not "nothing more to show". Return
			// an error so dispatchLive's Note-disclosure path picks it up
			// instead of silently rendering the insight with no detail at all.
			return nil, errors.New("could not read chronyc/timedatectl — is a time-sync daemon installed?")
		}
		return parseTimedatectl(out), nil
	}
	return parseChronyTracking(out), nil
}

func parseChronyTracking(out string) *models.Details {
	kv := make(map[string]string)
	for line := range strings.SplitSeq(out, "\n") {
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
		Type:  tableKV,
		Title: "chronyc tracking",
		KV:    kv,
	}
}

func parseTimedatectl(out string) *models.Details {
	kv := make(map[string]string)
	for line := range strings.SplitSeq(out, "\n") {
		parts := strings.SplitN(line, "=", 2)
		if len(parts) != 2 {
			continue
		}
		kv[parts[0]] = parts[1]
	}
	return &models.Details{
		Type:  tableKV,
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

	// sntp query (available without root on macOS) — a real outbound UDP query
	// to Apple's time servers, unlike chronyc/timedatectl above (which only
	// read local daemon state). Skip it under DSD_OFFLINE so a Clock
	// WARN/CRIT drill-down never phones out on an offline/air-gapped run.
	if os.Getenv("DSD_OFFLINE") == "" {
		sntpOut, err2 := runCmd(ctx, "sntp", "-t", "1", "time.apple.com")
		if err2 == nil {
			for line := range strings.SplitSeq(sntpOut, "\n") {
				if strings.Contains(line, "offset") || strings.Contains(line, "stratum") {
					kv["sntp_result"] = strings.TrimSpace(line)
					break
				}
			}
		}
	}

	return &models.Details{
		Type:  tableKV,
		Title: "Network time status",
		KV:    kv,
	}, nil
}
