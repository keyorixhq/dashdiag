package cmd

import (
	"strings"
	"testing"

	"github.com/keyorixhq/dashdiag/internal/models"
	"github.com/keyorixhq/dashdiag/internal/output"
)

// TestPrintDBVerdict pins the CRIT/WARN/healthy tally so a future insight type
// added to a DB collector can't silently land in neither bucket (the cmd
// verdict tally drift class, #275).
func TestPrintDBVerdict(t *testing.T) {
	healthy := captureStdout(t, func() { printDBVerdict(nil, output.ModePlain) })
	if !strings.Contains(healthy, "Databases healthy") {
		t.Errorf("no insights should read healthy, got:\n%s", healthy)
	}

	warnOnly := captureStdout(t, func() {
		printDBVerdict([]models.Insight{{Level: "WARN", Message: "replica lag high"}}, output.ModePlain)
	})
	if !strings.Contains(warnOnly, "1 database concern(s) found") {
		t.Errorf("one WARN insight should report 1 concern, got:\n%s", warnOnly)
	}
	if strings.Contains(warnOnly, "healthy") {
		t.Errorf("a WARN insight must not also read healthy, got:\n%s", warnOnly)
	}

	// A single CRIT alongside a WARN must escalate to the "issue(s)" wording —
	// and the count must be the combined crit+warn total, not crit alone,
	// since the WARN detail line above it still needs accounting for.
	mixed := captureStdout(t, func() {
		printDBVerdict([]models.Insight{
			{Level: "CRIT", Message: "primary unreachable"},
			{Level: "WARN", Message: "replica lag high"},
		}, output.ModePlain)
	})
	if !strings.Contains(mixed, "2 database issue(s) found") {
		t.Errorf("1 CRIT + 1 WARN should report 2 issue(s), got:\n%s", mixed)
	}
	if strings.Contains(mixed, "concern(s)") || strings.Contains(mixed, "healthy") {
		t.Errorf("a CRIT present must use issue(s) wording, not concern(s)/healthy, got:\n%s", mixed)
	}
}
