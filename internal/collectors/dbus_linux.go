//go:build linux

package collectors

import (
	"context"
	"strings"
	"time"

	"github.com/keyorixhq/dashdiag/internal/models"
)

// DBusCollector checks whether the D-Bus system message bus is active.
// D-Bus is a Tier-0 dependency: when it fails, all services that communicate
// via IPC (NetworkManager, systemd-logind, etc.) cascade-fail. This collector
// runs before the main parallel collector goroutines so its failure can be
// annotated onto all other failed-service insights.
type DBusCollector struct{}

func NewDBusCollector() *DBusCollector          { return &DBusCollector{} }
func (c *DBusCollector) Name() string           { return "DBus" }
func (c *DBusCollector) Timeout() time.Duration { return 3 * time.Second }

func (c *DBusCollector) Collect(ctx context.Context) (interface{}, error) {
	info := &models.DBusInfo{Available: true}

	out, err := localeSafeCmd(ctx, "systemctl", "is-active", "dbus.service").Output() // #nosec G204
	status := strings.TrimSpace(string(out))
	if err != nil {
		// systemctl exits non-zero when unit is not active.
		// Capture whatever status string was returned (e.g. "failed", "inactive").
		if status == "" {
			status = "unknown"
		}
	}

	info.Status = status
	info.Active = status == "active"

	if !info.Active {
		info.LastError = collectDBusLastError(ctx)
	}

	return info, nil
}

// collectDBusLastError pulls the most recent error line from the dbus journal.
// Returns empty string when journalctl is unavailable or produces no output.
func collectDBusLastError(ctx context.Context) string {
	out, err := localeSafeCmd(ctx, // #nosec G204
		"journalctl", "-u", "dbus.service", "-n", "5", "--no-pager", "-o", "cat",
	).Output()
	if err != nil || len(out) == 0 {
		return ""
	}
	// Walk lines in reverse to find the last non-empty error line.
	lines := strings.Split(strings.TrimSpace(string(out)), "\n")
	for i := len(lines) - 1; i >= 0; i-- {
		line := strings.TrimSpace(lines[i])
		if line != "" {
			return line
		}
	}
	return ""
}
