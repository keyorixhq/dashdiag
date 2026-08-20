package cmd

// cis_report_bsi_test.go — golden-output tests for cis.go's BSI report
// renderers (printBSIReport/printBSIReq/printBSISummary/bsiStatusColour/
// bsiIcon), mirroring the existing printCISReport/printNIS2Report tests in
// cis_report_test.go. No t.Parallel() (corrupts captureStdout's shared
// os.Stdout swap).

import (
	"strings"
	"testing"

	"github.com/keyorixhq/dashdiag/internal/cis"
	"github.com/keyorixhq/dashdiag/internal/models"
	"github.com/keyorixhq/dashdiag/internal/output"
)

func TestPrintBSIReportSections(t *testing.T) {
	baustein := cis.BSIBaustein{ID: "SYS.1.3", Title: "Server unter Linux und Unix", English: "Servers under Linux and Unix"}
	groups := []cis.BSIReqGroup{
		{
			Req:      cis.BSIRequirement{ID: "SYS.1.3.A2", Level: "B", English: "Careful assignment of user and group IDs"},
			Baustein: baustein,
			Status:   "FAIL",
			Fail:     1,
			Results: []models.CISResult{
				{ID: "5.2.1", Status: models.CISFail, Description: "root login enabled",
					Finding: "PermitRootLogin yes", Remediation: "set PermitRootLogin no"},
			},
		},
	}
	out := captureStdout(t, func() { printBSIReport(groups, false, output.ModePlain) })
	if !strings.Contains(out, "SYS.1.3") || !strings.Contains(out, "SERVERS UNDER LINUX AND UNIX") {
		t.Errorf("Baustein header should be rendered (uppercased English), got:\n%s", out)
	}
	if !strings.Contains(out, "SYS.1.3.A2") {
		t.Errorf("requirement ID should be rendered, got:\n%s", out)
	}
	if !strings.Contains(out, "PermitRootLogin yes") || !strings.Contains(out, "set PermitRootLogin no") {
		t.Errorf("a failed rule should show its finding and remediation, got:\n%s", out)
	}
	if !strings.Contains(out, "--bsi --json") {
		t.Errorf("expected the machine-readable-output tip, got:\n%s", out)
	}
}

func TestPrintBSIReportFailOnlyFilter(t *testing.T) {
	baustein := cis.BSIBaustein{ID: "SYS.1.3", English: "Servers under Linux and Unix"}
	groups := []cis.BSIReqGroup{
		{
			Req:      cis.BSIRequirement{ID: "SYS.1.3.A2", English: "req"},
			Baustein: baustein,
			Status:   "PARTIAL",
			Pass:     1, Fail: 1,
			Results: []models.CISResult{
				{ID: "5.2.1", Status: models.CISPass, Description: "pass rule"},
				{ID: "5.2.2", Status: models.CISFail, Description: "fail rule", Finding: "bad config"},
			},
		},
	}
	out := captureStdout(t, func() { printBSIReport(groups, true, output.ModePlain) })
	if strings.Contains(out, "pass rule") {
		t.Errorf("failOnly=true must suppress passing rules, got:\n%s", out)
	}
	if !strings.Contains(out, "fail rule") {
		t.Errorf("failOnly=true must still show the failing rule, got:\n%s", out)
	}
}

func TestPrintBSIReportUnmappedAlwaysShown(t *testing.T) {
	groups := []cis.BSIReqGroup{
		{
			Req:      cis.BSIRequirement{ID: "SYS.1.3.A9", English: "manual-only requirement"},
			Baustein: cis.BSIBaustein{ID: "SYS.1.3", English: "Servers under Linux and Unix"},
			Status:   "UNMAPPED",
		},
	}
	out := captureStdout(t, func() { printBSIReport(groups, true, output.ModePlain) })
	if !strings.Contains(out, "SYS.1.3.A9") {
		t.Errorf("UNMAPPED requirements must always show regardless of failOnly, got:\n%s", out)
	}
	if !strings.Contains(out, "No automated OS-level check") {
		t.Errorf("UNMAPPED requirements must show their explanation, got:\n%s", out)
	}
}

func TestPrintBSIReportSkippedVsUnverified(t *testing.T) {
	groups := []cis.BSIReqGroup{
		{
			Req:      cis.BSIRequirement{ID: "SYS.1.3.A3", English: "req"},
			Baustein: cis.BSIBaustein{ID: "SYS.1.3", English: "Servers under Linux and Unix"},
			Status:   "UNVERIFIED",
			Skipped:  2, Unverified: 1,
			Results: []models.CISResult{
				{ID: "1.1.1", Status: models.CISSkipped, Finding: "not applicable on this distro"},
				{ID: "1.1.2", Status: models.CISSkipped, Unverified: true, Finding: "could not confirm"},
			},
		},
	}
	out := captureStdout(t, func() { printBSIReport(groups, false, output.ModePlain) })
	if !strings.Contains(out, "not applicable on this distro") {
		t.Errorf("a plain skip should show its finding under the skip label, got:\n%s", out)
	}
	if !strings.Contains(out, "could not confirm") {
		t.Errorf("an unverified skip should show its finding under the unverified label, got:\n%s", out)
	}
	if !strings.Contains(out, "1 skipped") {
		t.Errorf("summary should count the non-unverified skip separately, got:\n%s", out)
	}
	if !strings.Contains(out, "1 unverified") {
		t.Errorf("summary should count the unverified skip, got:\n%s", out)
	}
}

func TestBSIStatusColour(t *testing.T) {
	cases := []string{"FAIL", "PARTIAL", "UNVERIFIED", "PASS", "UNMAPPED", ""}
	for _, status := range cases {
		// Only asserting it doesn't panic and returns something for both
		// colour states — the exact ANSI codes are shared helpers
		// (red/green/yellow/dim) already covered elsewhere.
		if got := bsiStatusColour(status, true); got == "" && status != "" {
			// dim(true) for the default branch is non-empty, so an empty
			// result here would indicate a genuinely missing case.
			t.Errorf("bsiStatusColour(%q, true) = empty, want a colour code", status)
		}
		_ = bsiStatusColour(status, false)
	}
}

func TestBSIIcon(t *testing.T) {
	cases := []struct {
		status string
		mode   output.OutputMode
		want   string
	}{
		{"PASS", output.ModeHuman, "✅"},
		{"FAIL", output.ModeHuman, "❌"},
		{"PARTIAL", output.ModeHuman, "⚠️"},
		{"UNVERIFIED", output.ModeHuman, "❓"},
		{"SKIP", output.ModeHuman, "⏭️"},
		{"PASS", output.ModePlain, "OK"},
		{"FAIL", output.ModePlain, "CRIT"},
	}
	for _, c := range cases {
		if got := bsiIcon(c.status, c.mode); !strings.Contains(got, c.want) {
			t.Errorf("bsiIcon(%q, %v) = %q, want it to contain %q", c.status, c.mode, got, c.want)
		}
	}
	// Unrecognized status falls through to the default "unknown" token rather
	// than panicking (matches cisIcon's own sibling default — see
	// output.StatusIcon/asciiOr's "unknown" case).
	if got := bsiIcon("SOMETHING_ELSE", output.ModePlain); !strings.Contains(got, "-") {
		t.Errorf("bsiIcon(unrecognized) = %q, want the default unknown token", got)
	}
}
