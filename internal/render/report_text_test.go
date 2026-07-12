package render

import (
	"strings"
	"testing"
	"time"
)

func TestRenderReportText(t *testing.T) {
	o := JSONOutput{
		Hostname: "web01", OS: "linux", Version: "1.2.3",
		Timestamp: time.Date(2026, 6, 8, 10, 0, 0, 0, time.UTC),
		Verdict:   "CRIT",
		Counts:    JSONCounts{Crit: 1, Warn: 1, Info: 0},
		Checks: []JSONCheck{
			{Name: "Disk", Status: "CRIT"},
			{Name: "Network", Status: "ERROR", Error: "timeout"},
			{Name: "CPU", Status: "OK"},
		},
		Insights: []JSONInsight{
			{Check: "Memory", Level: "WARN", Message: "RAM at 85%"},
			{Check: "Disk", Level: "CRIT", Message: "sda full", Hints: []string{"to fix: free space"}},
		},
	}
	out := RenderReportText(o)

	// Header + verdict line present.
	for _, want := range []string{"web01", "linux", "dsd 1.2.3", "VERDICT: CRIT", "1 CRIT, 1 WARN"} {
		if !strings.Contains(out, want) {
			t.Errorf("output missing %q\n---\n%s", want, out)
		}
	}
	// CRIT must be rendered before WARN (worst-first ordering).
	if strings.Index(out, "[CRIT] Disk") > strings.Index(out, "[WARN] Memory") {
		t.Errorf("CRIT should sort before WARN:\n%s", out)
	}
	// Hints rendered.
	if !strings.Contains(out, "-> to fix: free space") {
		t.Errorf("hint not rendered:\n%s", out)
	}
	// Errored checks surfaced; OK checks not listed as errored.
	if !strings.Contains(out, "errored") || !strings.Contains(out, "Network") {
		t.Errorf("errored check not surfaced:\n%s", out)
	}
	if strings.Contains(out, "CPU") {
		t.Errorf("OK check CPU should not appear in errored list:\n%s", out)
	}
}

func TestRenderReportTextNoFindings(t *testing.T) {
	o := JSONOutput{Hostname: "h", OS: "linux", Verdict: "OK"}
	out := RenderReportText(o)
	if !strings.Contains(out, "No findings") {
		t.Errorf("clean report should say no findings:\n%s", out)
	}
}

// TestOrDash covers both branches directly: empty input renders the dash
// placeholder, non-empty input passes through unchanged.
func TestOrDash(t *testing.T) {
	t.Parallel()
	if got := orDash(""); got != "—" {
		t.Errorf("orDash(\"\") = %q, want the dash placeholder", got)
	}
	if got := orDash("web01"); got != "web01" {
		t.Errorf("orDash(%q) = %q, want passthrough", "web01", got)
	}
}

// TestRenderReportText_SameSeverityChecknameTiebreak covers the sort
// tiebreak when two insights share the same severity: order falls back to
// comparing Check name (the existing test only has distinct severities).
func TestRenderReportText_SameSeverityChecknameTiebreak(t *testing.T) {
	t.Parallel()
	o := JSONOutput{
		Verdict: "WARN",
		Insights: []JSONInsight{
			{Check: "Zebra", Level: "WARN", Message: "z"},
			{Check: "Apple", Level: "WARN", Message: "a"},
		},
	}
	out := RenderReportText(o)
	if strings.Index(out, "[WARN] Apple") > strings.Index(out, "[WARN] Zebra") {
		t.Errorf("same-severity insights should tiebreak by Check name (Apple before Zebra):\n%s", out)
	}
}

// TestRenderReportText_EmptyHostAndOS exercises orDash's empty branch through
// the full renderer (not just the helper in isolation) — blank identity fields
// must render as the dash placeholder, not an empty gap in the header line.
func TestRenderReportText_EmptyHostAndOS(t *testing.T) {
	t.Parallel()
	o := JSONOutput{Verdict: "OK"}
	out := RenderReportText(o)
	if !strings.Contains(out, "DashDiag report — — · —") {
		t.Errorf("expected dash placeholders for blank hostname/OS, got:\n%s", out)
	}
}
