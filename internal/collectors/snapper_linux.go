package collectors

import (
	"context"
	"math"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/keyorixhq/dashdiag/internal/models"
)

var snapperDateRe = regexp.MustCompile(`(?:` +
	`(\w{3}\s+\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}\s+\d{4})` + // LC_ALL=C: "Wed May 13 20:39:27 2026"
	`|(\w{3}\s+\d{1,2}\s+\w{3}\s+\d{4}\s+\d{2}:\d{2}:\d{2}\s+[AP]M\s+\w+)` + // locale: "Wed 13 May 2026 08:39:27 PM CEST"
	`)`)

// CollectSnapper gathers Btrfs/Snapper snapshot health.
// Requires root or snapper group membership for full output.
func CollectSnapper(ctx context.Context) (*models.SnapperInfo, error) {
	info := &models.SnapperInfo{}

	if _, err := exec.LookPath("snapper"); err != nil {
		return info, nil // not installed — not an error
	}
	info.Available = true

	// Count configs
	configOut, err := runCmd(ctx, "snapper", "list-configs")
	if err == nil {
		for _, line := range strings.Split(configOut, "\n") {
			line = strings.TrimSpace(line)
			if line == "" || strings.HasPrefix(line, "Config") || strings.HasPrefix(line, "─") {
				continue
			}
			info.ConfigCount++
		}
	}

	// List all snapshots across all configs.
	// Snapper requires root or snapper group — if it fails, degrade gracefully.
	listOut, err := runCmd(ctx, "snapper", "list")
	if err != nil || strings.Contains(listOut, "No permissions") {
		info.Error = "run as root for snapshot details"
		return info, nil
	}
	return parseSnapperPlain(listOut, info), nil
}

// parseSnapperPlain parses `snapper list` table output.
func parseSnapperPlain(out string, info *models.SnapperInfo) *models.SnapperInfo {
	var lastTime time.Time
	var oldestTime time.Time
	var totalMiB float64

	for _, line := range strings.Split(out, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, "─") || strings.HasPrefix(line, "Config") {
			continue
		}
		// Skip header row
		if strings.Contains(line, "Type") && strings.Contains(line, "Date") {
			continue
		}
		info.SnapshotCount++

		// Date: extract with regex to handle Unicode box chars in line
		if m := snapperDateRe.FindString(line); m != "" {
			t := parseSnapperDate(m)
			if !t.IsZero() {
				if lastTime.IsZero() || t.After(lastTime) {
					lastTime = t
				}
				if oldestTime.IsZero() || t.Before(oldestTime) {
					oldestTime = t
				}
			}
		}

		// Space: find "X MiB" or "X.XX MiB"
		for _, field := range strings.Fields(line) {
			mib := parseMiB(field)
			if mib > 0 {
				totalMiB += mib
				break
			}
		}
	}

	if !lastTime.IsZero() {
		info.LastSnapshotH = int(time.Since(lastTime).Hours())
	} else {
		info.LastSnapshotH = -1
	}
	if !oldestTime.IsZero() {
		info.OldestDays = int(time.Since(oldestTime).Hours() / 24)
	}
	info.TotalSpaceGB = math.Round(totalMiB/1024*100) / 100

	return info
}

// parseMiB extracts float from strings like "16.26 MiB", "1.05 MiB"
func parseMiB(s string) float64 {
	s = strings.TrimSpace(s)
	if !strings.HasSuffix(s, "MiB") && !strings.HasSuffix(s, "GiB") {
		return 0
	}
	isGiB := strings.HasSuffix(s, "GiB")
	s = strings.TrimSuffix(strings.TrimSuffix(s, "MiB"), "GiB")
	s = strings.TrimSpace(s)
	v, err := strconv.ParseFloat(s, 64)
	if err != nil {
		return 0
	}
	if isGiB {
		return v * 1024
	}
	return v
}

// parseSnapperDate handles two snapper date formats:
//
//	LC_ALL=C (runCmd default): "Wed May 13 20:39:27 2026"  (24h, year at end)
//	System locale:             "Wed 13 May 2026 08:39:27 PM CEST" (12h, TZ suffix)
//
// Always parses in local timezone — snapper dates are wall-clock local time.
// time.Parse defaults to UTC which causes negative time.Since() on UTC+ systems.
func parseSnapperDate(s string) time.Time {
	s = strings.TrimSpace(s)

	// LC_ALL=C format: "Wed May 13 20:39:27 2026"
	// Go reference:    "Mon Jan 02 15:04:05 2006"
	for _, layout := range []string{
		"Mon Jan 02 15:04:05 2006",
		"Mon Jan _2 15:04:05 2006",
		"Mon Jan 2 15:04:05 2006",
	} {
		if t, err := time.ParseInLocation(layout, s, time.Local); err == nil {
			return t
		}
	}

	// Locale format: "Wed 13 May 2026 08:39:27 PM CEST"
	// Strip trailing TZ abbreviation (CEST, CET, UTC, etc.) but not AM/PM
	fields := strings.Fields(s)
	if len(fields) >= 2 {
		last := fields[len(fields)-1]
		if len(last) >= 2 && len(last) <= 5 &&
			last == strings.ToUpper(last) &&
			last != "AM" && last != "PM" {
			fields = fields[:len(fields)-1]
		}
	}
	// Reorder: "Wed 13 May 2026 08:39:27 PM" -> "Wed May 13 2026 08:39:27 PM"
	if len(fields) >= 4 {
		reordered := strings.Join(append([]string{fields[0], fields[2], fields[1]}, fields[3:]...), " ")
		for _, layout := range []string{
			"Mon Jan 02 2006 03:04:05 PM",
			"Mon Jan _2 2006 03:04:05 PM",
			"Mon Jan 2 2006 03:04:05 PM",
		} {
			if t, err := time.ParseInLocation(layout, reordered, time.Local); err == nil {
				return t
			}
		}
	}
	return time.Time{}
}
