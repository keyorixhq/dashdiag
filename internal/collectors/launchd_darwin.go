//go:build darwin

package collectors

import (
	"bufio"
	"context"
	"path/filepath"
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

func (c *LaunchdCollector) Collect(ctx context.Context) (any, error) {
	info := &models.LaunchdInfo{}

	// launchctl list — prints all loaded services:
	// PID   Status  Label
	// 1234  -       com.apple.Spotlight
	// -     0       com.apple.screensaver
	// -     1       com.example.myapp   ← failed (non-zero exit, no PID)
	out, err := runCmd(ctx, "launchctl", "list")
	if err != nil {
		// A total scan failure must not read the same as "checked every
		// service, zero failures" — Checked stays false so checkLaunchd can
		// tell the difference.
		return info, nil
	}

	info.Checked = true
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

		pid := 0
		if pidStr != "-" {
			pid, _ = strconv.Atoi(pidStr)
		}
		status := 0
		if statusStr != "-" {
			status, _ = strconv.Atoi(statusStr)
		}
		// Failed = not running + non-zero last exit code
		isFailed := pid == 0 && status != 0

		// Skip Apple internal kernel/OS noise. A "com.apple." Label is
		// self-reported by whatever plist declares it — a plist dropped in a
		// user-writable LaunchAgents directory can claim any Label it wants.
		// Trust the prefix for the bulk of (non-failing) noise, but a FAILED
		// "com.apple." entry must have a plist actually present under the
		// SIP-protected system launchd directories before its failure is
		// suppressed; otherwise the suppression itself becomes the perfect
		// place to hide a failing persistence mechanism.
		if isLaunchdNoise(label) && (!isFailed || !isAppleLabel(label) || isGenuineAppleLaunchdPlist(label)) {
			total--
			continue
		}

		if pid > 0 {
			running++
		}
		if isFailed {
			failed = append(failed, models.LaunchdService{
				Label:  label,
				Status: status,
			})
		}
	}
	return total, running, failed
}

// isAppleLabel reports whether label carries the "com.apple." prefix that
// isLaunchdNoise treats as blanket-trusted noise.
func isAppleLabel(label string) bool {
	return strings.HasPrefix(strings.ToLower(label), "com.apple.")
}

// systemLaunchdDirs are the SIP-protected directories where Apple's own
// launchd services are defined — not writable outside of a system update,
// unlike ~/Library/LaunchAgents or /Library/LaunchAgents.
var systemLaunchdDirs = []string{
	"/System/Library/LaunchAgents",
	"/System/Library/LaunchDaemons",
}

// isGenuineAppleLaunchdPlist reports whether label resolves to an actual
// plist under a SIP-protected system launchd directory (checked via statFile,
// the source-routed stat used package-wide, so this replays under `dsd
// replay` instead of hitting the live filesystem). label.plist is the
// filename convention Apple's own daemons follow; a label with no matching
// file there did not come from a system-owned plist.
func isGenuineAppleLaunchdPlist(label string) bool {
	for _, dir := range systemLaunchdDirs {
		if _, err := statFile(filepath.Join(dir, label+".plist")); err == nil {
			return true
		}
	}
	return false
}

// isLaunchdNoise returns true for services that are safe to ignore when "failed".
//
// On macOS, hundreds of com.apple.* daemons are demand-launched: they start,
// do their job, exit (often with a non-zero code), and get relaunched next time
// they're needed. launchctl reports them as "failed" but macOS considers this
// normal. They are never actionable — we can't fix them and they don't indicate
// a real problem.
//
// The rule: suppress ALL com.apple.* failures. The only failures worth surfacing
// are third-party services the user or an admin explicitly installed:
//   - com.docker.*, com.homebrew.*, com.microsoft.*, com.google.*
//   - org.* (Homebrew, open source daemons)
//   - io.* (many popular macOS tools)
//   - application.* entries with no PID are running apps that have quit — ignore
func isLaunchdNoise(label string) bool {
	lower := strings.ToLower(label)

	// All Apple built-in daemons — always noise when "failed".
	// Apple's on-demand daemons exit after completing their task; launchctl
	// reports a non-zero exit as "failed" but macOS considers it normal.
	if strings.HasPrefix(lower, "com.apple.") {
		return true
	}

	// GUI app labels (e.g. application.com.google.Chrome.123.456) — not daemons
	if strings.HasPrefix(lower, "application.") {
		return true
	}

	return false
}
