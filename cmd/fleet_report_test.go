package cmd

import (
	"fmt"
	"strings"
	"testing"

	"github.com/keyorixhq/dashdiag/internal/fleet"
	"github.com/keyorixhq/dashdiag/internal/output"
	"github.com/keyorixhq/dashdiag/internal/render"
)

// Golden-output tests for fleet.go's table renderers. No t.Parallel()
// (corrupts captureStdout's shared os.Stdout swap). Set DSD_NO_NUDGE so the
// waitlist nudge (already covered in fleet_nudge_test.go) doesn't add noise.

func TestPrintFleetTable(t *testing.T) {
	t.Setenv("DSD_NO_NUDGE", "1")
	summary := fleet.Summarize([]fleet.Result{
		{Host: "web01", Reachable: true, Worst: "OK"},
		{Host: "web02", Reachable: true, Worst: "CRIT", Crit: 1, TopIssue: "disk full"},
		{Host: "web03", Reachable: false, Error: "connection refused"},
	})
	out := captureStdout(t, func() { printFleetTable(summary, output.ModePlain) })
	if !strings.Contains(out, "web01") || !strings.Contains(out, "web02") || !strings.Contains(out, "web03") {
		t.Errorf("all three hosts should be listed, got:\n%s", out)
	}
	if !strings.Contains(out, "disk full") {
		t.Errorf("the top issue for a CRIT host should be shown, got:\n%s", out)
	}
	// An unreachable host must show its connection error, not a stale top-issue.
	if !strings.Contains(out, "connection refused") {
		t.Errorf("an unreachable host should show its error instead of TopIssue, got:\n%s", out)
	}
	if !strings.Contains(out, "3 host(s)") {
		t.Errorf("the summary line should count all hosts, got:\n%s", out)
	}
}

// TestPrintFleetTable_SanitizesControlChars guards against terminal-escape
// injection via a remote host's TopIssue/Error text — both come from another
// machine's `dsd health --json` output over SSH, which a compromised or
// malicious remote host fully controls.
func TestPrintFleetTable_SanitizesControlChars(t *testing.T) {
	t.Setenv("DSD_NO_NUDGE", "1")
	const esc = "\x1b[2J"
	summary := fleet.Summarize([]fleet.Result{
		{Host: "web01", Reachable: true, Worst: "CRIT", Crit: 1, TopIssue: "disk full" + esc},
		{Host: "web02", Reachable: false, Error: "connection refused" + esc},
	})
	out := captureStdout(t, func() { printFleetTable(summary, output.ModePlain) })
	if strings.Contains(out, esc) {
		t.Errorf("printFleetTable must strip terminal escape sequences from TopIssue/Error, got:\n%q", out)
	}
}

// TestPrintFleetIssues_SanitizesControlChars guards against terminal-escape
// injection via grouped-issue Check/Sample text sourced from remote hosts.
func TestPrintFleetIssues_SanitizesControlChars(t *testing.T) {
	const esc = "\x1b[2J"
	summary := fleet.Summarize([]fleet.Result{
		{Host: "web01", Reachable: true, Worst: "WARN", Warn: 1,
			Issues: []fleet.Issue{{Check: "Disk" + esc, Level: "WARN", Message: "disk at 85%" + esc}}},
	})
	out := captureStdout(t, func() { printFleetIssues(summary, output.ModePlain) })
	if strings.Contains(out, esc) {
		t.Errorf("printFleetIssues must strip terminal escape sequences from Check/Sample, got:\n%q", out)
	}
}

// TestPrintFleetTableWithNudge covers the waitlist-nudge line printed by
// printFleetTable itself — TestPrintFleetTable above always silences it via
// DSD_NO_NUDGE, so the nudge-rendering branch was never exercised.
func TestPrintFleetTableWithNudge(t *testing.T) {
	t.Setenv("DSD_NO_NUDGE", "")
	t.Setenv("DSD_NO_UPDATE_CHECK", "")
	summary := fleet.Summarize([]fleet.Result{
		{Host: "web01", Reachable: true, Worst: "OK"},
		{Host: "web02", Reachable: true, Worst: "OK"},
	})
	out := captureStdout(t, func() { printFleetTable(summary, output.ModeHuman) })
	if !strings.Contains(out, "dashdiag.sh/plans") {
		t.Errorf("a multi-host, non-silenced run should print the waitlist nudge, got:\n%s", out)
	}
}

func TestPrintFleetIssues(t *testing.T) {
	none := fleet.Summarize([]fleet.Result{{Host: "web01", Reachable: true, Worst: "OK"}})
	if out := captureStdout(t, func() { printFleetIssues(none, output.ModePlain) }); out != "" {
		t.Errorf("no issues should print nothing, got:\n%s", out)
	}

	withIssues := fleet.Summarize([]fleet.Result{
		{Host: "web01", Reachable: true, Worst: "WARN", Warn: 1, Issues: []fleet.Issue{{Check: "Disk", Level: "WARN", Message: "disk at 85%"}}},
		{Host: "web02", Reachable: true, Worst: "WARN", Warn: 1, Issues: []fleet.Issue{{Check: "Disk", Level: "WARN", Message: "disk at 90%"}}},
	})
	out := captureStdout(t, func() { printFleetIssues(withIssues, output.ModePlain) })
	if !strings.Contains(out, "Disk") {
		t.Errorf("a fleet-wide grouped issue should name the check, got:\n%s", out)
	}
}

// TestPrintFleetIssues_Outlier covers the "outlier" scope branch, where the
// issue's single host is shown by name instead of an "N/M" ratio (3+
// reachable hosts, only one carrying the issue).
func TestPrintFleetIssues_Outlier(t *testing.T) {
	summary := fleet.Summarize([]fleet.Result{
		{Host: "web01", Reachable: true, Worst: "OK"},
		{Host: "web02", Reachable: true, Worst: "OK"},
		{Host: "web03", Reachable: true, Worst: "WARN", Warn: 1, Issues: []fleet.Issue{{Check: "Disk", Level: "WARN", Message: "disk at 90%"}}},
	})
	out := captureStdout(t, func() { printFleetIssues(summary, output.ModePlain) })
	if !strings.Contains(out, "web03") {
		t.Errorf("an outlier issue should show the single affected host by name, got:\n%s", out)
	}
	if strings.Contains(out, "1/3") {
		t.Errorf("an outlier issue must not show the N/M ratio form, got:\n%s", out)
	}
}

// TestBuildFleetReport verifies the fleet.Summary → render.FleetReport conversion.
func TestBuildFleetReport(t *testing.T) {
	t.Parallel()
	summary := fleet.Summarize([]fleet.Result{
		{Host: "web01", Reachable: true, Worst: "CRIT", Crit: 1, TopIssue: "disk full",
			Issues: []fleet.Issue{{Check: "Disk", Level: "CRIT", Message: "disk full"}}},
		{Host: "web02", Reachable: true, Worst: "OK"},
		{Host: "web03", Reachable: false, Error: "connection refused"},
	})
	report := buildFleetReport(summary)
	if report.Verdict != "CRIT" {
		t.Errorf("expected CRIT verdict, got %q", report.Verdict)
	}
	if report.VerdictClass != "crit" {
		t.Errorf("expected crit class, got %q", report.VerdictClass)
	}
	if report.Total != 3 {
		t.Errorf("expected total=3, got %d", report.Total)
	}
	if report.CountCrit != 1 || report.CountOK != 1 || report.CountUnreachable != 1 {
		t.Errorf("count mismatch: crit=%d ok=%d unreachable=%d", report.CountCrit, report.CountOK, report.CountUnreachable)
	}
	if len(report.Hosts) != 3 {
		t.Fatalf("expected 3 host rows, got %d", len(report.Hosts))
	}
	// Unreachable host should carry error as top issue and use "error" status class.
	var unreachable *render.FleetHostRow
	for i := range report.Hosts {
		if report.Hosts[i].Host == "web03" {
			unreachable = &report.Hosts[i]
		}
	}
	if unreachable == nil {
		t.Fatal("web03 not in host rows")
	}
	if unreachable.StatusClass != "error" {
		t.Errorf("unreachable host should have status class 'error', got %q", unreachable.StatusClass)
	}
	if unreachable.TopIssue != "connection refused" {
		t.Errorf("unreachable host top issue should be the error, got %q", unreachable.TopIssue)
	}
}

// TestBuildFleetReport_Warn covers the WARN verdict branch in buildFleetReport.
func TestBuildFleetReport_Warn(t *testing.T) {
	t.Parallel()
	summary := fleet.Summarize([]fleet.Result{
		{Host: "web01", Reachable: true, Worst: "WARN", Warn: 1, TopIssue: "disk 85%"},
		{Host: "web02", Reachable: true, Worst: "OK"},
	})
	report := buildFleetReport(summary)
	if report.VerdictClass != "warn" {
		t.Errorf("expected warn class, got %q", report.VerdictClass)
	}
	if report.VerdictText == "" {
		t.Error("expected non-empty VerdictText for WARN verdict")
	}
}

// TestBuildFleetReport_AllOK covers the default/OK verdict branch in buildFleetReport.
func TestBuildFleetReport_AllOK(t *testing.T) {
	t.Parallel()
	summary := fleet.Summarize([]fleet.Result{
		{Host: "web01", Reachable: true, Worst: "OK"},
	})
	report := buildFleetReport(summary)
	if report.VerdictClass != "ok" {
		t.Errorf("expected ok class, got %q", report.VerdictClass)
	}
	if report.VerdictText == "" {
		t.Error("expected non-empty VerdictText for OK verdict")
	}
}

// TestPrintFleetIssues_TruncatedAt15 covers the "N more (see --json)" branch
// when the number of distinct grouped issues exceeds the 15-row display limit.
func TestPrintFleetIssues_TruncatedAt15(t *testing.T) {
	var results []fleet.Result
	for i := 0; i < 20; i++ {
		results = append(results, fleet.Result{
			Host: fmt.Sprintf("web%02d", i), Reachable: true, Worst: "WARN", Warn: 1,
			Issues: []fleet.Issue{{Check: fmt.Sprintf("Check%02d", i), Level: "WARN", Message: "distinct issue"}},
		})
	}
	summary := fleet.Summarize(results)
	out := captureStdout(t, func() { printFleetIssues(summary, output.ModePlain) })
	if !strings.Contains(out, "more (see --json)") {
		t.Errorf("more than 15 distinct issues should truncate with a 'more' hint, got:\n%s", out)
	}
}
