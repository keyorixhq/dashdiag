package render

import (
	"errors"
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

	// internal-render-03-03: a collector error never becomes a CRIT/WARN
	// insight — it only ever produces an INFO "check could not run" disclosure
	// — so a run where every collector failed had zero CRIT/WARN insights and
	// fell straight to the "DASHDIAG OK - all checks passed" default, exactly
	// the false-OK a monitoring plugin line must never emit.
	t.Run("a failed collector with no other findings is WARNING, not OK", func(t *testing.T) {
		failedRes := []runner.Result{{Name: "Disk", Err: errors.New("boom")}, {Name: "CPU"}}
		line, code := NagiosLine(failedRes, nil)
		if code != 1 || !strings.HasPrefix(line, "DASHDIAG WARNING") {
			t.Fatalf("got %q code=%d, want WARNING exit 1", line, code)
		}
		if !strings.Contains(line, "Disk") {
			t.Errorf("failed check name not surfaced: %q", line)
		}
	})

	t.Run("a failed collector alongside a real WARN is still WARNING, naming both", func(t *testing.T) {
		failedRes := []runner.Result{{Name: "Disk", Err: errors.New("boom")}, {Name: "CPU"}}
		ins := []models.Insight{{Level: "WARN", Check: "Swap"}}
		line, code := NagiosLine(failedRes, ins)
		if code != 1 || !strings.HasPrefix(line, "DASHDIAG WARNING") {
			t.Fatalf("got %q code=%d", line, code)
		}
		if !strings.Contains(line, "Swap") || !strings.Contains(line, "Disk") {
			t.Errorf("expected both the real WARN and the failed check named: %q", line)
		}
	})

	t.Run("a failed collector alongside a CRIT stays CRITICAL, naming the failure too", func(t *testing.T) {
		failedRes := []runner.Result{{Name: "Disk"}, {Name: "Network", Err: errors.New("timeout")}}
		ins := []models.Insight{{Level: "CRIT", Check: "Disk"}}
		line, code := NagiosLine(failedRes, ins)
		if code != 2 || !strings.HasPrefix(line, "DASHDIAG CRITICAL") {
			t.Fatalf("got %q code=%d", line, code)
		}
		if !strings.Contains(line, "Network") {
			t.Errorf("failed check name not surfaced alongside CRIT: %q", line)
		}
	})

	// C1: a collector can run without error and still be unable to determine
	// the specific thing it checks (C2: /dev/kmsg unreadable for a reason
	// other than non-root) — that's an Unverified INFO insight, not a
	// Result.Err, so the internal-render-03-03 fix above (which only looks at
	// r.Err) never sees it. Same false-OK shape, different source.
	t.Run("an unverified check with no other findings is WARNING, not OK", func(t *testing.T) {
		ins := []models.Insight{{Level: "INFO", Check: "Logs", Message: "kmsg unreadable", Unverified: true}}
		line, code := NagiosLine(res, ins)
		if code != 1 || !strings.HasPrefix(line, "DASHDIAG WARNING") {
			t.Fatalf("got %q code=%d, want WARNING exit 1", line, code)
		}
		if !strings.Contains(line, "Logs") {
			t.Errorf("unverified check name not surfaced: %q", line)
		}
	})

	t.Run("an unverified check alongside a CRIT stays CRITICAL", func(t *testing.T) {
		ins := []models.Insight{
			{Level: "CRIT", Check: "Disk"},
			{Level: "INFO", Check: "Logs", Message: "kmsg unreadable", Unverified: true},
		}
		line, code := NagiosLine(res, ins)
		if code != 2 || !strings.HasPrefix(line, "DASHDIAG CRITICAL") {
			t.Fatalf("got %q code=%d, want CRITICAL exit 2 (an unverified check must not outrank a real CRIT)", line, code)
		}
	})

	t.Run("a repeated collector failure is deduped by name", func(t *testing.T) {
		failedRes := []runner.Result{
			{Name: "Disk", Err: errors.New("boom")},
			{Name: "Disk", Err: errors.New("boom again")},
		}
		line, code := NagiosLine(failedRes, nil)
		if code != 1 {
			t.Fatalf("code=%d, want 1", code)
		}
		if strings.Count(line, "Disk") != 1 {
			t.Errorf("expected Disk named once, got: %q", line)
		}
	})
}
