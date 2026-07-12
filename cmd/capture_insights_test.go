package cmd

// capture_insights_test.go — guards the capture→mock round-trip against the
// lossy-collapse bug: a check that emits several insights (Hardening: weak MACs
// + NOPASSWD + X11 …) must keep ALL of them through capture and mock, not just
// the highest-severity one the row carries. Found on an AWS EC2 box where the
// SSH weak-MAC WARN silently vanished from a captured fixture.

import (
	"testing"

	"github.com/keyorixhq/dashdiag/internal/models"
)

// the multi-insight Hardening case that exposed the bug, plus a single Logs
// insight to prove order across checks is preserved.
var multiInsightInput = []captureInsight{
	{Check: "Hardening", Level: "WARN", Message: "NOPASSWD sudo for: admin", Hints: []string{"to inspect: sudo -l"}},
	{Check: "Hardening", Level: "WARN", Message: "SSH weak MAC(s) enabled: hmac-sha1"},
	{Check: "Hardening", Level: "INFO", Message: "SSH X11Forwarding enabled"},
	{Check: "Logs", Level: "INFO", Message: "no text log fallback detected"},
}

func TestCaptureInsights_PreservesAllAndOrder(t *testing.T) {
	got := captureInsights(multiInsightInput)
	if len(got) != len(multiInsightInput) {
		t.Fatalf("captureInsights dropped insights: got %d, want %d", len(got), len(multiInsightInput))
	}
	for i, in := range multiInsightInput {
		if got[i].Check != in.Check || got[i].Message != in.Message || got[i].Level != in.Level {
			t.Errorf("insight %d not preserved faithfully: got %+v, want %+v", i, got[i], in)
		}
	}
	// The specific finding that vanished in the field.
	if !hasMockInsight(got, "Hardening", "SSH weak MAC(s) enabled: hmac-sha1") {
		t.Error("the weak-MAC WARN must survive capture — that was the original bug")
	}
}

func TestResolveMockInsights_PrefersFullList(t *testing.T) {
	// A fixture whose Hardening row carries only ONE message (NOPASSWD) but whose
	// full Insights list carries all three. Mock must render all three.
	fix := MockFixture{
		Rows: []MockRow{
			{Name: "Hardening", Level: "WARN", Message: "NOPASSWD sudo for: admin"},
			{Name: "Logs", Level: "INFO", Message: "no text log fallback detected"},
		},
		Insights: captureInsights(multiInsightInput),
	}
	got := resolveMockInsights(fix)
	if len(got) != 4 {
		t.Fatalf("resolveMockInsights must render the full captured set, got %d want 4", len(got))
	}
	// OK/empty levels are filtered; the weak-MAC WARN must be present.
	if !hasResolvedInsight(got, "Hardening", "SSH weak MAC(s) enabled: hmac-sha1") {
		t.Error("weak-MAC WARN missing from mock render — the full list was not used")
	}
}

// TestResolveMockInsights_FullListFiltersOKLevel covers the fix.Insights-path
// OK/empty-level skip itself — TestResolveMockInsights_PrefersFullList above
// has a comment claiming this but multiInsightInput never actually contains
// an OK-level entry, so that branch was never exercised.
func TestResolveMockInsights_FullListFiltersOKLevel(t *testing.T) {
	fix := MockFixture{
		Rows: []MockRow{{Name: "Disk", Level: "OK", Inline: "10%"}},
		Insights: []MockInsight{
			{Check: "Disk", Level: "OK", Message: "all filesystems healthy"},
			{Check: "Disk", Level: "WARN", Message: "/ at 85%"},
		},
	}
	got := resolveMockInsights(fix)
	if len(got) != 1 {
		t.Fatalf("an OK-level insight in fix.Insights must be filtered, got %d want 1", len(got))
	}
	if got[0].Message != "/ at 85%" {
		t.Errorf("the surviving insight should be the WARN one, got %+v", got[0])
	}
}

func TestResolveMockInsights_FallbackForOldFixtures(t *testing.T) {
	// Pre-insights fixture: no Insights list → reconstruct one per non-OK row.
	fix := MockFixture{
		Rows: []MockRow{
			{Name: "CPU Load", Level: "OK", Inline: "2%"}, // OK rows produce no insight
			{Name: "Hardening", Level: "WARN", Message: "SSH allows password authentication"},
		},
	}
	got := resolveMockInsights(fix)
	if len(got) != 1 {
		t.Fatalf("fallback must reconstruct one insight per non-OK row, got %d want 1", len(got))
	}
	if got[0].Check != "Hardening" || got[0].Level != "WARN" {
		t.Errorf("fallback insight wrong: %+v", got[0])
	}
}

func hasMockInsight(list []MockInsight, check, msg string) bool {
	for _, i := range list {
		if i.Check == check && i.Message == msg {
			return true
		}
	}
	return false
}

func hasResolvedInsight(list []models.Insight, check, msg string) bool {
	for _, i := range list {
		if i.Check == check && i.Message == msg {
			return true
		}
	}
	return false
}
