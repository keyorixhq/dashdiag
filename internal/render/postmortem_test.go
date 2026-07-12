package render

import (
	"strings"
	"testing"
	"time"

	"github.com/keyorixhq/dashdiag/internal/baseline"
	"github.com/keyorixhq/dashdiag/internal/models"
	"github.com/keyorixhq/dashdiag/internal/output"
)

// TestRenderPostMortem covers the full happy path: WARN/CRIT/INFO status
// labels in the state table, the Issues section (CRIT before WARN), and
// deduplicated Recommended Investigation Steps built from both groups' hints.
func TestRenderPostMortem(t *testing.T) {
	t.Parallel()
	snap := &baseline.Snapshot{
		Hostname:  "host1",
		Timestamp: time.Date(2026, 6, 19, 12, 0, 0, 0, time.UTC),
		Checks: []baseline.CheckResult{
			{Name: "Disk", Status: "CRIT", Value: "/ 95%"},
			{Name: "Memory", Status: "WARN", Value: "88%"},
			{Name: "Clock", Status: "INFO", Value: "drift 2ms"},
			{Name: "CPU Load", Status: "OK", Value: "10%"},
		},
	}
	insights := []models.Insight{
		{Check: "Disk", Level: "CRIT", Message: "disk full", Hints: []string{"to fix: extend volume", "to fix: extend volume"}},
		{Check: "Memory", Level: "WARN", Message: "high usage", Hints: []string{"to inspect: top"}},
	}

	got := RenderPostMortem("prod incident", snap, insights, output.ModeHuman)

	for _, want := range []string{
		"#### Incident: prod incident",
		"host1",
		"❌ CRIT", "disk full",
		"⚠️ WARN", "high usage",
		"ℹ️ INFO", // Clock
		"✅ OK",    // CPU Load
		"#### Issues Detected",
		"#### Recommended Investigation Steps",
		"1. `to fix: extend volume`",
		"to inspect: top",
		"#### Timeline",
		"#### Resolution",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("postmortem missing %q\n---\n%s", want, got)
		}
	}

	// Hints deduplicate: "to fix: extend volume" appears twice in the Disk
	// insight's Hints slice (both rendered as-is under Issues Detected) but must
	// be listed only ONCE as a numbered Recommended Investigation Step.
	if strings.Count(got, "1. `to fix: extend volume`") != 1 {
		t.Errorf("expected exactly one numbered dedup'd step for the repeated hint:\n%s", got)
	}
	if strings.Contains(got, "2. `to fix: extend volume`") {
		t.Errorf("repeated hint must be deduplicated, not listed twice as a step:\n%s", got)
	}

	// CRIT must render before WARN in the Issues section.
	if strings.Index(got, "disk full") > strings.Index(got, "high usage") {
		t.Errorf("CRIT should render before WARN in Issues Detected:\n%s", got)
	}
}

// TestRenderPostMortem_NoIssues covers the branch where there are no CRIT/WARN
// insights: the Issues Detected and Recommended Investigation Steps sections
// must both be entirely absent (not empty headers).
func TestRenderPostMortem_NoIssues(t *testing.T) {
	t.Parallel()
	snap := &baseline.Snapshot{
		Hostname:  "host1",
		Timestamp: time.Date(2026, 6, 19, 12, 0, 0, 0, time.UTC),
		Checks:    []baseline.CheckResult{{Name: "CPU Load", Status: "OK", Value: "5%"}},
	}
	got := RenderPostMortem("quiet incident", snap, nil, output.ModeHuman)
	if strings.Contains(got, "#### Issues Detected") {
		t.Errorf("no CRIT/WARN insights — Issues Detected section should be absent:\n%s", got)
	}
	if strings.Contains(got, "#### Recommended Investigation Steps") {
		t.Errorf("no hints — Recommended Investigation Steps section should be absent:\n%s", got)
	}
}
