//go:build darwin

package collectors

import (
	"context"
	"strings"
	"time"

	"github.com/keyorixhq/dashdiag/internal/models"
)

type AuthCollector struct{}

func NewAuthCollector() *AuthCollector          { return &AuthCollector{} }
func (c *AuthCollector) Name() string           { return "Auth" }
func (c *AuthCollector) Timeout() time.Duration { return 8 * time.Second }

func (c *AuthCollector) Collect(ctx context.Context) (interface{}, error) {
	// Only meaningful if sshd is running — no sshd means no auth surface to monitor.
	if !sshdRunningDarwin(ctx) {
		return &models.AuthInfo{}, nil // Available=false → row hidden
	}

	info := &models.AuthInfo{Available: true}

	// Query macOS unified log for sshd auth failures in the last 24 hours.
	// This is the equivalent of grepping auth.log on Linux.
	out, err := runCmd(ctx, "log", "show",
		"--predicate", `process == "sshd" AND (eventMessage CONTAINS "Failed" OR eventMessage CONTAINS "Invalid user")`,
		"--last", "24h",
		"--style", "compact",
	)
	if err != nil {
		// log show may fail if SIP restricts access — still mark as available
		// since sshd is running, just mark not checked
		return info, nil
	}

	info.Checked = true
	for _, line := range strings.Split(out, "\n") {
		if line == "" {
			continue
		}
		info.FailedLast24h++
	}

	return info, nil
}

// sshdRunningDarwin checks whether SSH is accepting connections on macOS.
// macOS uses on-demand socket activation: no persistent sshd process exists
// when idle, even with Remote Login enabled. pgrep -x sshd therefore finds nothing.
// Checking port 22 is the reliable non-root indicator.
func sshdRunningDarwin(ctx context.Context) bool {
	// nc -z exits 0 when port is open, non-zero when closed/refused.
	_, err := runCmd(ctx, "nc", "-z", "-w1", "127.0.0.1", "22")
	return err == nil
}
