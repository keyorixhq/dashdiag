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
	// D-Bus health here is the state of the *systemd* dbus.service unit. On a
	// non-systemd host (Alpine/OpenRC, minimal containers) `systemctl` is absent,
	// so the check can't run — gate off rather than report a phantom "D-Bus failed"
	// CRIT. systemdPresentViaSource (not platform.SystemdAvailable) so the gate is
	// recorded/replayed rather than probing the replaying machine — see its comment.
	if !systemdPresentViaSource() {
		return nil, nil
	}

	info := &models.DBusInfo{Available: true}

	// Query the bus by its canonical name "dbus", NOT "dbus.service". On modern
	// Debian/Ubuntu (and the VMware Ubuntu templates) the running unit may be
	// dbus.socket / an alias / dbus-broker.service, and `is-active dbus.service`
	// can return empty+nonzero ("unknown") even while the bus is fully active —
	// `is-active dbus` resolves the alias and reports "active". Querying the
	// wrong name was the root of a false "D-Bus failed" CRIT (TRIAGE §M).
	out, err := runCmdOutput(ctx, "systemctl", "is-active", "dbus")
	status := strings.TrimSpace(out)
	if status == "" {
		// Empty output means systemctl couldn't report a state at all (timeout,
		// missing unit lookup). This is "couldn't determine", NOT "failed" —
		// leave it explicit so the heuristic doesn't treat unknown as down.
		status = "unknown"
	}
	_ = err // is-active exits non-zero for inactive/failed; the status string is authoritative.

	info.Status = status
	info.Active = status == "active"

	// Only pull a journal error line when the bus is *confirmed* down (an
	// explicit failed/inactive from systemctl), never on "unknown" — on unknown
	// the bus is likely fine and the journal's last line is usually a success
	// ("Successfully activated service …"), which must not masquerade as an error.
	if status == "failed" || status == "inactive" {
		info.LastError = collectDBusLastError(ctx)
	}

	return info, nil
}

// collectDBusLastError pulls the most recent *error-level* line from the dbus
// journal. Returns empty string when journalctl is unavailable, produces no
// output, or has no error-priority lines. Filtering by priority (rather than
// taking the last non-empty line) prevents success messages like
// "Successfully activated service org.freedesktop.timedate1" from being
// reported as the last error (TRIAGE §M).
func collectDBusLastError(ctx context.Context) string {
	out, err := runCmd(ctx,
		// -p err: only priority error and above; -o cat: message text only.
		"journalctl", "-u", "dbus.service", "-p", "err", "-n", "5", "--no-pager", "-o", "cat",
	)
	if err != nil || len(out) == 0 {
		return ""
	}
	// Walk lines in reverse to find the last non-empty line (already filtered to
	// error priority by journalctl -p err).
	lines := strings.Split(strings.TrimSpace(out), "\n")
	for i := len(lines) - 1; i >= 0; i-- {
		line := strings.TrimSpace(lines[i])
		if line != "" {
			return line
		}
	}
	return ""
}
