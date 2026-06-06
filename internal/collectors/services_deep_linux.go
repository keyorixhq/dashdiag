//go:build linux

package collectors

import (
	"context"
	"strconv"
	"strings"
	"time"

	"github.com/keyorixhq/dashdiag/internal/models"
)

// ServicesDeepCollector runs systemd health checks:
// failed units + last journal lines, boot offenders, journal integrity,
// masked unit detection, and daemon-reload status.
// Linux/systemd only. The notlinux stub returns an empty struct.
type ServicesDeepCollector struct{}

func NewServicesDeepCollector() *ServicesDeepCollector { return &ServicesDeepCollector{} }

func (c *ServicesDeepCollector) Name() string           { return "ServicesDeep" }
func (c *ServicesDeepCollector) Timeout() time.Duration { return 15 * time.Second }

func (c *ServicesDeepCollector) Collect(ctx context.Context) (interface{}, error) {
	info := &models.ServicesDeepInfo{JournalHealthy: true}

	// 1. Failed units
	failedOut, err := runCmd(ctx, "systemctl", "list-units",
		"--failed", "--plain", "--no-legend", "--no-pager")
	if err == nil {
		info.FailedUnits = parseFailedUnits(failedOut)
	}

	// 2. Last journal lines + exit code per failed unit (parallel, capped)
	for i := range info.FailedUnits {
		unit := &info.FailedUnits[i]
		logOut, err := runCmd(ctx, "journalctl", "-u", unit.Name,
			"-n", "8", "--no-pager", "--output=short", "--no-hostname")
		if err == nil {
			unit.LastLogLines = parseJournalLines(logOut)
		}
		// Exit code from systemctl show
		showOut, err := runCmd(ctx, "systemctl", "show", unit.Name,
			"--property=ExecMainStatus,ActiveState,SubState")
		if err == nil {
			parseUnitShow(showOut, unit)
		}
	}

	// 3. Daemon-reload check — units with changed files
	info.NeedsDaemonReload = collectNeedsDaemonReload(ctx)

	// 4. Masked units
	maskedOut, err := runCmd(ctx, "systemctl", "list-units",
		"--type=service", "--state=masked", "--plain", "--no-legend", "--no-pager")
	if err == nil {
		info.MaskedUnits = parseMaskedUnits(maskedOut)
	}

	// 5. Journal integrity
	verifyOut, err := runCmd(ctx, "journalctl", "--verify")
	if err != nil {
		info.JournalHealthy = false
		info.JournalLastValid = parseJournalVerifyError(verifyOut + err.Error())
	}

	// 6. Boot offenders (top 5 real services, exclude .device/.socket/.mount)
	blameOut, err := runCmd(ctx, "systemd-analyze", "blame", "--no-pager")
	if err == nil {
		info.BootOffenders = parseBlame(blameOut, 5)
	}

	// 7. User units (only if user systemd daemon is running)
	info.UserUnits = collectUserUnits(ctx)

	return info, nil
}

// ── parsers (pure functions — exported via lvm_parse.go pattern) ──────────

// parseFailedUnits parses `systemctl list-units --failed --plain --no-legend`.
// Output columns: UNIT LOAD ACTIVE SUB DESCRIPTION
// Example: "postgresql.service loaded failed failed PostgreSQL Database"
func parseFailedUnits(out string) []models.SystemdUnit {
	var units []models.SystemdUnit
	for _, line := range strings.Split(out, "\n") {
		fields := strings.Fields(line)
		// Need at least: UNIT LOAD ACTIVE SUB
		if len(fields) < 4 {
			continue
		}
		name := fields[0]
		// Skip lines that are summary text ("0 loaded units listed" etc.)
		if !strings.Contains(name, ".") {
			continue
		}
		units = append(units, models.SystemdUnit{
			Name:        name,
			ActiveState: fields[2],
			SubState:    fields[3],
		})
	}
	return units
}

// parseJournalLines extracts the last N meaningful log lines from journalctl output.
// Strips timestamp, hostname, and unit prefix to keep just the message body.
func parseJournalLines(out string) []string {
	var lines []string
	for _, line := range strings.Split(out, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		// journalctl short format: "May 19 10:00:00 host unit[pid]: message"
		// Find the ": " after the process name and take everything after it.
		if idx := strings.Index(line, "]: "); idx >= 0 {
			msg := strings.TrimSpace(line[idx+3:])
			if msg != "" {
				lines = append(lines, msg)
			}
			continue
		}
		// Fallback: keep the whole line if it doesn't match expected format
		lines = append(lines, line)
	}
	return lines
}

// parseUnitShow parses `systemctl show <unit> --property=ExecMainStatus,ActiveState,SubState`.
// Updates the unit in-place with exit code and state.
func parseUnitShow(out string, unit *models.SystemdUnit) {
	for _, line := range strings.Split(out, "\n") {
		kv := strings.SplitN(line, "=", 2)
		if len(kv) != 2 {
			continue
		}
		switch kv[0] {
		case "ExecMainStatus":
			unit.ExitCode, _ = strconv.Atoi(kv[1])
		case "ActiveState":
			if unit.ActiveState == "" {
				unit.ActiveState = kv[1]
			}
		case "SubState":
			if unit.SubState == "" {
				unit.SubState = kv[1]
			}
		}
	}
}

// collectNeedsDaemonReload returns unit names that have NeedsDaemonReload=yes.
// Queries a batch of loaded service units to keep overhead low.
func collectNeedsDaemonReload(ctx context.Context) []string {
	// Get the list of loaded service units
	listOut, err := runCmd(ctx, "systemctl", "list-units",
		"--type=service", "--state=loaded", "--plain", "--no-legend", "--no-pager")
	if err != nil {
		return nil
	}
	var unitNames []string
	for _, line := range strings.Split(listOut, "\n") {
		fields := strings.Fields(line)
		if len(fields) < 1 {
			continue
		}
		name := fields[0]
		if strings.HasSuffix(name, ".service") {
			unitNames = append(unitNames, name)
		}
	}
	if len(unitNames) == 0 {
		return nil
	}

	// Batch query — systemctl accepts multiple unit names in one call
	args := append([]string{"show", "--property=Id,NeedsDaemonReload"}, unitNames...)
	showOut, err := runCmd(ctx, "systemctl", args...)
	if err != nil {
		return nil
	}
	return parseNeedsDaemonReload(showOut)
}

// parseNeedsDaemonReload parses batched `systemctl show --property=Id,NeedsDaemonReload`
// output and returns unit names with NeedsDaemonReload=yes.
// systemctl separates units with blank lines; each block has Id= and NeedsDaemonReload=.
func parseNeedsDaemonReload(out string) []string {
	var result []string
	var currentID string
	for _, line := range strings.Split(out, "\n") {
		kv := strings.SplitN(strings.TrimSpace(line), "=", 2)
		if len(kv) != 2 {
			continue
		}
		switch kv[0] {
		case "Id":
			currentID = kv[1]
		case "NeedsDaemonReload":
			if kv[1] == "yes" && currentID != "" {
				result = append(result, currentID)
			}
		}
	}
	return result
}

// parseMaskedUnits parses `systemctl list-units --state=masked` output.
// Returns unit names. The masked state is a silent trap — units look disabled
// but cannot be enabled without explicit unmasking.
func parseMaskedUnits(out string) []string {
	var units []string
	for _, line := range strings.Split(out, "\n") {
		fields := strings.Fields(line)
		if len(fields) < 1 {
			continue
		}
		name := fields[0]
		if strings.Contains(name, ".") {
			units = append(units, name)
		}
	}
	return units
}

// parseJournalVerifyError extracts the "last valid entry" timestamp from
// `journalctl --verify` error output when corruption is detected.
func parseJournalVerifyError(out string) string {
	for _, line := range strings.Split(out, "\n") {
		if strings.Contains(line, "last valid entry") || strings.Contains(line, "PASS") {
			return strings.TrimSpace(line)
		}
	}
	return ""
}

// parseBlame parses `systemd-analyze blame` and returns the top N real service
// offenders, excluding .device, .socket, .mount, .target, and .path units
// which appear in the output but are not actionable.
func parseBlame(out string, topN int) []models.BootOffender {
	var offenders []models.BootOffender

	for _, line := range strings.Split(out, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}

		// Fields: duration unit  e.g. "4.210s postgresql.service"
		// Duration may be: "4.210s", "1min 2.300s", "2ms"
		// Unit name is always the last field
		unitName := fields[len(fields)-1]

		// Skip non-service unit types (shared with parseBlameSlowUnits — see
		// blameSkipSuffixes — so the two blame parsers can't drift apart).
		if isNonServiceBlameUnit(unitName) {
			continue
		}

		// Parse duration from leading fields (before unit name)
		durationStr := strings.Join(fields[:len(fields)-1], " ")
		ms := parseDurationMs(durationStr)

		offenders = append(offenders, models.BootOffender{
			Unit:       unitName,
			DurationMs: ms,
		})
		if len(offenders) >= topN {
			break
		}
	}
	return offenders
}

// parseDurationMs converts systemd-analyze blame duration strings to milliseconds.
// Handles: "4.210s", "2min 4.210s", "450ms", "1h 2min 3.000s"
func parseDurationMs(s string) int {
	s = strings.TrimSpace(s)
	total := 0

	// Walk through space-separated tokens: "1min", "2.300s", "450ms"
	for _, token := range strings.Fields(s) {
		token = strings.TrimSpace(token)
		switch {
		case strings.HasSuffix(token, "ms"):
			n, _ := strconv.ParseFloat(strings.TrimSuffix(token, "ms"), 64)
			total += int(n)
		case strings.HasSuffix(token, "min"):
			n, _ := strconv.ParseFloat(strings.TrimSuffix(token, "min"), 64)
			total += int(n * 60000)
		case strings.HasSuffix(token, "h"):
			n, _ := strconv.ParseFloat(strings.TrimSuffix(token, "h"), 64)
			total += int(n * 3600000)
		case strings.HasSuffix(token, "s"):
			n, _ := strconv.ParseFloat(strings.TrimSuffix(token, "s"), 64)
			total += int(n * 1000)
		}
	}
	return total
}

// collectUserUnits checks if a systemd user daemon is running for the current
// user, and if so collects its failed units.
func collectUserUnits(ctx context.Context) *models.UserUnitsInfo {
	// Check if user daemon is reachable
	_, err := runCmd(ctx, "systemctl", "--user", "is-system-running")
	if err != nil {
		// Exit code != 0 is normal for "degraded"; connection refused means no user daemon
		if strings.Contains(err.Error(), "Failed to connect") ||
			strings.Contains(err.Error(), "No such file") {
			return &models.UserUnitsInfo{Available: false}
		}
	}

	info := &models.UserUnitsInfo{Available: true}
	failedOut, err := runCmd(ctx, "systemctl", "--user",
		"list-units", "--failed", "--plain", "--no-legend", "--no-pager")
	if err == nil {
		info.Failed = parseFailedUnits(failedOut)
		// Fetch last log lines for user failed units too
		for i := range info.Failed {
			unit := &info.Failed[i]
			logOut, err := runCmd(ctx, "journalctl", "--user",
				"-u", unit.Name, "-n", "5", "--no-pager", "--output=short")
			if err == nil {
				unit.LastLogLines = parseJournalLines(logOut)
			}
		}
	}
	return info
}
