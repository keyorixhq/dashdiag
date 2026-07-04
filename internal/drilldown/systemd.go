package drilldown

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"runtime"

	"github.com/keyorixhq/dashdiag/internal/models"
)

// FailedUnitLogs fetches the last n log lines for a failed systemd unit.
func FailedUnitLogs(ctx context.Context, unit string, lines int) (*models.Details, error) {
	if runtime.GOOS == "darwin" || unit == "" {
		return nil, nil
	}
	if _, err := exec.LookPath("journalctl"); err != nil {
		return nil, nil // no journald on this host — nothing to report, not a gap
	}

	out, err := runCmd(ctx, "journalctl", "-u", unit,
		fmt.Sprintf("-n%d", lines), "--no-pager", "--output=short")
	if err != nil {
		// A genuinely logless unit and a permission-denied journal read (reading
		// the system journal needs root or `systemd-journal` group membership)
		// both hit this branch; distinguishing them from stdout alone isn't
		// possible (runCmd captures only stdout), but non-root is the common
		// real-world case, so surface an honest caveat instead of silently
		// implying "no journal entries" when we simply couldn't read it.
		if os.Geteuid() != 0 {
			return &models.Details{
				Type:  "log_tail",
				Title: "Recent journal output for " + unit,
				Note:  "could not read the journal for " + unit + " (needs root or systemd-journal group membership)",
			}, nil
		}
		return nil, nil
	}

	return &models.Details{
		Type:  "log_tail",
		Title: "Recent journal output for " + unit,
		KV:    map[string]string{"log_tail": out},
	}, nil
}
