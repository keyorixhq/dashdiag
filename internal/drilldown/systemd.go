package drilldown

import (
	"context"
	"fmt"
	"runtime"

	"github.com/keyorixhq/dashdiag/internal/models"
)

// FailedUnitLogs fetches the last n log lines for a failed systemd unit.
func FailedUnitLogs(ctx context.Context, unit string, lines int) (*models.Details, error) {
	if runtime.GOOS == "darwin" || unit == "" {
		return nil, nil
	}

	out, err := runCmd(ctx, "journalctl", "-u", unit,
		fmt.Sprintf("-n%d", lines), "--no-pager", "--output=short")
	if err != nil {
		// journalctl may not be installed or unit may have no logs
		return nil, nil
	}

	return &models.Details{
		Type:  "log_tail",
		Title: "Recent journal output for " + unit,
		KV:    map[string]string{"log_tail": out},
	}, nil
}
