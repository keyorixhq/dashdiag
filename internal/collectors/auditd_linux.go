//go:build linux

package collectors

import (
	"context"
	"os"
	"os/exec"
	"strings"
	"time"

	"github.com/keyorixhq/dashdiag/internal/models"
)

type AuditCollector struct{}

func NewAuditCollector() *AuditCollector         { return &AuditCollector{} }
func (c *AuditCollector) Name() string           { return "Auditd" }
func (c *AuditCollector) Timeout() time.Duration { return 4 * time.Second }

func (c *AuditCollector) Collect(ctx context.Context) (interface{}, error) {
	info := &models.AuditInfo{}

	if _, err := exec.LookPath("auditctl"); err != nil {
		return info, nil
	}
	info.Available = true

	// Check if the daemon is running. systemctl is-active fails on a non-systemd
	// host (OpenRC/SysV) even when auditd is running, which would false-alarm
	// "auditd installed but not running — compliance logging inactive" in the
	// verdict. Confirm via the process too (same fallback as cron detection).
	if _, err := runCmd(ctx, "systemctl", "is-active", "auditd"); err == nil {
		info.Running = true
	} else if _, err := runCmd(ctx, "pgrep", "-x", "auditd"); err == nil {
		info.Running = true
	}

	// Rule count
	out, err := runCmd(ctx, "auditctl", "-l")
	if err == nil {
		lines := strings.Split(strings.TrimSpace(out), "\n")
		for _, l := range lines {
			if strings.HasPrefix(l, "-") {
				info.RulesLoaded++
			}
		}
	}

	// Audit log size
	if fi, err := os.Stat("/var/log/audit/audit.log"); err == nil {
		info.AuditLogSizeGB = float64(fi.Size()) / (1024 * 1024 * 1024)
	}

	// Recent event count from audit log
	out, err = runCmd(ctx, "ausearch", "-ts", "1hour ago", "--raw")
	if err == nil {
		info.EventsLast1h = strings.Count(out, "type=")
	}

	return info, nil
}

func IsAuditdPresent() bool {
	_, err := exec.LookPath("auditctl")
	return err == nil
}

func parseAuditctlRules(out string) int {
	n := 0
	for _, line := range strings.Split(out, "\n") {
		if strings.HasPrefix(strings.TrimSpace(line), "-") {
			n++
		}
	}
	return n
}

func parseAuditEventCount(out string) int {
	return strings.Count(out, "type=")
}
