//go:build linux

package collectors

import (
	"context"
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

	if _, err := lookPath("auditctl"); err != nil {
		return info, nil
	}
	info.Available = true

	// Check if the daemon is running. systemctl is-active fails on a non-systemd
	// host (OpenRC/SysV) even when auditd is running, which would false-alarm
	// "auditd installed but not running — compliance logging inactive" in the
	// verdict. Confirm via the running process too (matching /proc/<pid>/comm —
	// portable where `pgrep -x` is not; same fallback as cron detection).
	if _, err := runCmd(ctx, "systemctl", "is-active", "auditd"); err == nil {
		info.Running = true
	} else if anyProcessNamed("auditd") {
		info.Running = true
	}

	// Rule count. auditctl -l typically requires root; on EACCES/failure the
	// zero value must not read as "genuinely zero rules loaded" — a non-root
	// run against a host with hundreds of loaded rules would otherwise report
	// rules_loaded=0, indistinguishable from an unconfigured auditd, to any
	// consumer (raw --json, a downstream compliance tool) reading the count
	// directly (internal-collectors-01-03).
	out, err := runCmd(ctx, "auditctl", "-l")
	if err == nil {
		lines := strings.Split(strings.TrimSpace(out), "\n")
		for _, l := range lines {
			if strings.HasPrefix(l, "-") {
				info.RulesLoaded++
			}
		}
	} else {
		info.RulesUnreadable = true
	}

	// Audit log size. The 0700 root:root audit dir denies non-root — set an
	// explicit sentinel so that case isn't confused with a genuinely small log.
	if fi, err := statFile("/var/log/audit/audit.log"); err == nil {
		info.AuditLogSizeGB = float64(fi.Size) / (1024 * 1024 * 1024)
	} else {
		info.AuditLogSizeUnreadable = true
	}

	// Recent event count from audit log. Same false-OK risk as RulesLoaded
	// above — ausearch also typically requires root.
	out, err = runCmd(ctx, "ausearch", "-ts", "1hour ago", "--raw")
	if err == nil {
		info.EventsLast1h = strings.Count(out, "type=")
	} else {
		info.EventsUnreadable = true
	}

	return info, nil
}

func IsAuditdPresent() bool {
	_, err := lookPath("auditctl")
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
