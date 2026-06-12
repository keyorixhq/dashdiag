package render

import (
	"strings"
	"testing"

	"github.com/keyorixhq/dashdiag/internal/models"
	"github.com/keyorixhq/dashdiag/internal/runner"
)

func TestNagiosLine(t *testing.T) {
	res := []runner.Result{{Name: "CPU"}, {Name: "Disk"}}

	t.Run("clean is OK exit 0", func(t *testing.T) {
		line, code := NagiosLine(res, nil)
		if code != 0 || !strings.HasPrefix(line, "DASHDIAG OK") {
			t.Fatalf("got %q code=%d", line, code)
		}
	})

	t.Run("warnings → WARNING exit 1, subsystems named", func(t *testing.T) {
		ins := []models.Insight{
			{Level: "WARN", Check: "Swap"},
			{Level: "WARN", Check: "Hardening"},
			{Level: "INFO", Check: "Drives"}, // INFO must not count
		}
		line, code := NagiosLine(res, ins)
		if code != 1 || !strings.HasPrefix(line, "DASHDIAG WARNING") {
			t.Fatalf("got %q code=%d", line, code)
		}
		if !strings.Contains(line, "Swap") || !strings.Contains(line, "Hardening") {
			t.Errorf("subsystems not named: %q", line)
		}
		if strings.Contains(line, "Drives") {
			t.Errorf("INFO should not appear: %q", line)
		}
	})

	t.Run("any CRIT → CRITICAL exit 2", func(t *testing.T) {
		ins := []models.Insight{
			{Level: "CRIT", Check: "Disk"},
			{Level: "WARN", Check: "Swap"},
		}
		line, code := NagiosLine(res, ins)
		if code != 2 || !strings.HasPrefix(line, "DASHDIAG CRITICAL") {
			t.Fatalf("got %q code=%d", line, code)
		}
		if !strings.Contains(line, "1 critical") || !strings.Contains(line, "1 warning") {
			t.Errorf("counts wrong: %q", line)
		}
	})

	t.Run("a subsystem at CRIT is not also listed as a warning", func(t *testing.T) {
		ins := []models.Insight{
			{Level: "CRIT", Check: "Disk"},
			{Level: "WARN", Check: "Disk"}, // same subsystem, lower level
		}
		line, code := NagiosLine(res, ins)
		if code != 2 {
			t.Fatalf("code=%d", code)
		}
		// "1 critical" with no ", N warning" — Disk counted once, at CRIT.
		if strings.Contains(line, "warning") {
			t.Errorf("Disk should only count as critical: %q", line)
		}
	})

	t.Run("dedupes repeated insights for one subsystem", func(t *testing.T) {
		ins := []models.Insight{
			{Level: "WARN", Check: "Network"},
			{Level: "WARN", Check: "Network"},
		}
		line, _ := NagiosLine(res, ins)
		if !strings.Contains(line, "1 warning") {
			t.Errorf("expected deduped count of 1: %q", line)
		}
	})
}
