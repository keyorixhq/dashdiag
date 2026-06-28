package cmd

import (
	"strings"
	"testing"

	"github.com/keyorixhq/dashdiag/internal/models"
	"github.com/keyorixhq/dashdiag/internal/output"
)

// TestPrintSystemdHealthNotQueried: on a non-systemd host (or when systemctl errors)
// `systemctl list-units --failed` never runs, so FailedUnits is empty NOT because
// there are no failed units but because nothing was queried. The renderer must not
// print the green "Failed units: none" (false-OK) — it must say it couldn't query.
func TestPrintSystemdHealthNotQueried(t *testing.T) {
	notQueried := &models.ServicesDeepInfo{FailedUnitsQueried: false, JournalHealthy: true}
	out := captureStdout(t, func() { printSystemdHealth(notQueried, output.ModeHuman) })
	if line := failedUnitsLine(out); !strings.Contains(line, "not queried") {
		t.Errorf("un-queried systemd 'Failed units' line should say 'not queried', got %q", line)
	}

	// Queried with no failures → genuine "none" on the Failed units line.
	queried := &models.ServicesDeepInfo{FailedUnitsQueried: true, JournalHealthy: true}
	out2 := captureStdout(t, func() { printSystemdHealth(queried, output.ModeHuman) })
	if line := failedUnitsLine(out2); !strings.Contains(line, "none") {
		t.Errorf("queried-with-no-failures 'Failed units' line should say 'none', got %q", line)
	}
}

// failedUnitsLine returns the rendered "Failed units" line (other lines also
// contain "none"/"healthy", so assertions must target this line specifically).
func failedUnitsLine(out string) string {
	for _, l := range strings.Split(out, "\n") {
		if strings.Contains(l, "Failed units") {
			return l
		}
	}
	return ""
}
