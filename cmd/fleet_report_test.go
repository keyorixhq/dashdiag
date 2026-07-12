package cmd

import (
	"fmt"
	"strings"
	"testing"

	"github.com/keyorixhq/dashdiag/internal/fleet"
	"github.com/keyorixhq/dashdiag/internal/output"
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
