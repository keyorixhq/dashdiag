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

// TestRenderPostMortem_SanitizesControlChars guards Finding
// internal-render-03-06: check.Name/Value, ins.Check/Message, ins.Hints, and
// Hostname can all carry attacker-controlled substrings (e.g. a process name
// from /proc, settable via prctl(PR_SET_NAME)) with no character filtering.
// This postmortem is explicitly designed to be pasted into incident
// channels/tickets, and markdown doesn't escape raw control/ANSI bytes any
// more than a terminal does, so control bytes must be stripped.
func TestRenderPostMortem_SanitizesControlChars(t *testing.T) {
	t.Parallel()
	evil := "evil\x1b[2Jname"
	snap := &baseline.Snapshot{
		Hostname:  "host" + evil,
		Timestamp: time.Date(2026, 6, 19, 12, 0, 0, 0, time.UTC),
		Checks:    []baseline.CheckResult{{Name: "FDLimits" + evil, Status: "WARN", Value: "value" + evil}},
	}
	insights := []models.Insight{
		{Check: "FDLimits" + evil, Level: "WARN", Message: "message" + evil, Hints: []string{"hint" + evil}},
	}
	got := RenderPostMortem("incident", snap, insights, output.ModeHuman)
	if strings.ContainsRune(got, 0x1b) {
		t.Errorf("RenderPostMortem output still contains a raw ESC byte:\n%s", got)
	}
	if !strings.Contains(got, "evil[2Jname") { // ESC byte stripped, surrounding printable text survives
		t.Errorf("expected printable payload to survive sanitization, got:\n%s", got)
	}
}

// TestRenderPostMortem_EscapesPipeInTableCells guards Finding
// internal-render-03-06: output.SanitizeControl strips control/ANSI bytes but
// does not escape a literal '|', which is an ordinary printable rune. A
// value containing '|' (e.g. an Insight.Message derived from a
// /proc/pid/comm process name, attacker-settable via prctl(PR_SET_NAME))
// would otherwise break/extend the markdown table row's structure when this
// postmortem is pasted into Slack/Jira/GitHub. Both check.Name and the
// rendered value must have literal '|' escaped to "\|".
func TestRenderPostMortem_EscapesPipeInTableCells(t *testing.T) {
	t.Parallel()
	snap := &baseline.Snapshot{
		Hostname:  "host1",
		Timestamp: time.Date(2026, 6, 19, 12, 0, 0, 0, time.UTC),
		Checks:    []baseline.CheckResult{{Name: "Weird|Check", Status: "WARN", Value: "a|b|c"}},
	}
	got := RenderPostMortem("incident", snap, nil, output.ModeHuman)
	if !strings.Contains(got, "Weird\\|Check") {
		t.Errorf("expected check name pipe to be escaped as \\|, got:\n%s", got)
	}
	if !strings.Contains(got, "a\\|b\\|c") {
		t.Errorf("expected value pipe to be escaped as \\|, got:\n%s", got)
	}
	// The row must contain exactly the 5 unescaped pipes that delimit the 4
	// markdown table columns ("| a | b | c | d |") — any additional bare '|'
	// would mean an escape was missed and the row structure is broken.
	for line := range strings.SplitSeq(got, "\n") {
		if strings.Contains(line, "Weird") {
			if n := strings.Count(line, "|") - strings.Count(line, "\\|"); n != 5 {
				t.Errorf("table row has unexpected unescaped pipe count %d, line: %q", n, line)
			}
		}
	}
}

// TestRenderPostMortem_EscapesBackticks guards Finding internal-render-03-06:
// output.SanitizeControl strips control/ANSI bytes but does nothing about
// literal backticks. The Recommended Investigation Steps section wraps each
// hint in a single-backtick inline code span (“ `%s` “) — even ONE
// embedded backtick in the hint would close that span early. The Issues
// Detected section has no surrounding delimiter at all, but a hint whose
// content is its own run of 3+ backticks could still open an unintended
// fenced block mid-document. escapeMarkdownBackticks must neutralize every
// backtick in Check/Message/Hints before either section renders it.
func TestRenderPostMortem_EscapesBackticks(t *testing.T) {
	t.Parallel()
	snap := &baseline.Snapshot{
		Hostname:  "host1",
		Timestamp: time.Date(2026, 6, 19, 12, 0, 0, 0, time.UTC),
		Checks:    []baseline.CheckResult{{Name: "Weird`Check", Status: "CRIT", Value: "bad"}},
	}
	insights := []models.Insight{
		{Check: "Weird`Check", Level: "CRIT", Message: "msg`with`backtick", Hints: []string{"cmd `with` backtick"}},
	}
	got := RenderPostMortem("incident", snap, insights, output.ModeHuman)

	// Scope this to the Issues Detected / Recommended Investigation Steps
	// sections onward — the System State table (above them) renders
	// check.Name/Value straight from the snapshot with only pipe-escaping
	// (a separate, already-covered fix; out of scope for this finding) and
	// legitimately still contains the raw "Weird`Check"/"bad" cell content.
	afterIssues := got[strings.Index(got, "#### Issues Detected"):]
	if strings.Contains(afterIssues, "`with`") || strings.Contains(afterIssues, "Weird`Check") || strings.Contains(afterIssues, "msg`with`backtick") {
		t.Errorf("expected embedded backticks in Check/Message/Hints to be escaped, got:\n%s", afterIssues)
	}
	// The single-backtick inline span around the numbered Recommended
	// Investigation Step must still have exactly its own two delimiting
	// backticks — not extra ones from the unescaped hint content.
	for line := range strings.SplitSeq(got, "\n") {
		if strings.HasPrefix(line, "1. `") {
			if n := strings.Count(line, "`"); n != 2 {
				t.Errorf("expected exactly 2 delimiting backticks on the numbered step, got %d: %q", n, line)
			}
		}
	}
	// The escaped substitute must still be present (proves the content
	// itself was rendered, not silently dropped).
	if !strings.Contains(got, "ˋ") {
		t.Errorf("expected the escaped backtick substitute in output, got:\n%s", got)
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
