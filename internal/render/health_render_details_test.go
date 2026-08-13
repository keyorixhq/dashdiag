package render

import (
	"strings"
	"testing"

	"github.com/keyorixhq/dashdiag/internal/models"
	"github.com/keyorixhq/dashdiag/internal/output"
	"github.com/keyorixhq/dashdiag/internal/runner"
)

// NOTE: none of the tests below that call captureStdout use t.Parallel() —
// captureStdout swaps the shared global os.Stdout for its duration, so
// concurrent callers race on it (see hints_test.go's captureStdout doc
// comment and health_mock_test.go's own note on this convention).

// TestRenderDetailsTable covers the Title + Columns/Rows table-rendering
// branch (column widths, header, and row alignment).
func TestRenderDetailsTable(t *testing.T) {
	r := NewRenderer(output.ModeHuman)
	d := &models.Details{
		Title:   "Zombies",
		Columns: []string{"PID", "Parent"},
		Rows:    [][]string{{"123", "cron"}, {"456", "nginx"}},
	}
	out := captureStdout(t, func() { r.renderDetails(d) })
	for _, want := range []string{"Zombies:", "PID", "Parent", "123", "cron", "456", "nginx"} {
		if !strings.Contains(out, want) {
			t.Errorf("table details missing %q\n---\n%s", want, out)
		}
	}
}

// TestRenderDetailsTable_StripsControlChars guards terminal escape injection
// on table cells — Details rows are largely sourced from journalctl/proc
// output, which is attacker-influenced and must not carry raw control
// bytes (ESC starts ANSI/OSC escape sequences) to the terminal. It must
// also not mutate the underlying model, since --json/--yaml output reuses
// the same Details struct and needs the raw values.
func TestRenderDetailsTable_StripsControlChars(t *testing.T) {
	r := NewRenderer(output.ModeHuman)
	evilPID := "123\x1b]0;pwned\x07"
	d := &models.Details{
		Title:   "Zombies",
		Columns: []string{"PID", "Parent"},
		Rows:    [][]string{{evilPID, "cron"}},
	}
	out := captureStdout(t, func() { r.renderDetails(d) })
	if strings.Contains(out, "\x1b") {
		t.Errorf("renderDetails table output still contains ESC byte: %q", out)
	}
	if !strings.Contains(out, "123]0;pwned") {
		t.Errorf("renderDetails table output missing sanitized cell text: %q", out)
	}
	if d.Rows[0][0] != evilPID {
		t.Errorf("renderDetails must not mutate the underlying model: Rows[0][0] = %q, want unchanged %q", d.Rows[0][0], evilPID)
	}
}

// TestRenderDetailsLogTail covers the log_tail Type branch: each line of the
// KV["log_tail"] value is printed as its own indented line.
func TestRenderDetailsLogTail(t *testing.T) {
	r := NewRenderer(output.ModeHuman)
	d := &models.Details{
		Type: "log_tail",
		KV:   map[string]string{"log_tail": "line one\nline two\n"},
	}
	out := captureStdout(t, func() { r.renderDetails(d) })
	if !strings.Contains(out, "line one") || !strings.Contains(out, "line two") {
		t.Errorf("log_tail details missing expected lines:\n%s", out)
	}
}

// TestRenderDetailsLogTail_StripsControlChars guards terminal escape
// injection on log_tail content — sourced directly from journalctl output.
func TestRenderDetailsLogTail_StripsControlChars(t *testing.T) {
	r := NewRenderer(output.ModeHuman)
	d := &models.Details{
		Type: "log_tail",
		KV:   map[string]string{"log_tail": "line one\x1b]0;pwned\x07\nline two"},
	}
	out := captureStdout(t, func() { r.renderDetails(d) })
	if strings.Contains(out, "\x1b") {
		t.Errorf("renderDetails log_tail output still contains ESC byte: %q", out)
	}
	if !strings.Contains(out, "line one]0;pwned") {
		t.Errorf("renderDetails log_tail output missing sanitized line: %q", out)
	}
}

// TestRenderDetailsKV covers the plain key/value branch (Type != log_tail,
// no Rows) — each KV pair renders as "key: value".
func TestRenderDetailsKV(t *testing.T) {
	r := NewRenderer(output.ModeHuman)
	d := &models.Details{KV: map[string]string{"driver": "nvme"}}
	out := captureStdout(t, func() { r.renderDetails(d) })
	if !strings.Contains(out, "driver") || !strings.Contains(out, "nvme") {
		t.Errorf("KV details missing expected pair:\n%s", out)
	}
}

// TestRenderDetailsNote covers the trailing Note line.
func TestRenderDetailsNote(t *testing.T) {
	r := NewRenderer(output.ModeHuman)
	d := &models.Details{Note: "sampled over 60s"}
	out := captureStdout(t, func() { r.renderDetails(d) })
	if !strings.Contains(out, "note: sampled over 60s") {
		t.Errorf("expected note line, got:\n%s", out)
	}
}

// TestRenderDetailsEmpty covers the no-title/no-rows/no-kv/no-note case —
// renderDetails must not panic and should produce no output.
func TestRenderDetailsEmpty(t *testing.T) {
	r := NewRenderer(output.ModeHuman)
	out := captureStdout(t, func() { r.renderDetails(&models.Details{}) })
	if out != "" {
		t.Errorf("empty Details should print nothing, got %q", out)
	}
}

// TestSortedResultsUnknownNamesPreserveOrder covers the "both unknown" tie
// branch: two collector names absent from displayOrder must keep their
// original relative order (stable sort), rather than being reordered.
func TestSortedResultsUnknownNamesPreserveOrder(t *testing.T) {
	t.Parallel()
	results := []runner.Result{
		{Name: "ZCollector"},
		{Name: "ACollector"},
		{Name: "Memory"}, // known — sorts to its displayOrder position
	}
	got := sortedResults(results)
	// Memory is in displayOrder near the front; the two unknowns are stable
	// relative to each other and pushed after all known names.
	names := make([]string, len(got))
	for i, r := range got {
		names[i] = r.Name
	}
	if names[0] != "Memory" {
		t.Errorf("known collector should sort before unknowns, got order %v", names)
	}
	zi, ai := -1, -1
	for i, n := range names {
		if n == "ZCollector" {
			zi = i
		}
		if n == "ACollector" {
			ai = i
		}
	}
	if zi < 0 || ai < 0 || zi > ai {
		t.Errorf("unknown collectors must preserve original relative order (Z before A in input), got %v", names)
	}
}

// TestLevelToStatusKeyDefault covers the default branch (an unrecognized or
// "OK" level maps to "ok").
func TestLevelToStatusKeyDefault(t *testing.T) {
	t.Parallel()
	cases := map[string]string{"CRIT": "fail", "WARN": "warn", "INFO": "info", "OK": "ok", "": "ok", "garbage": "ok"}
	for level, want := range cases {
		if got := levelToStatusKey(level); got != want {
			t.Errorf("levelToStatusKey(%q) = %q, want %q", level, got, want)
		}
	}
}

// TestPrintAllMockJSONMode covers PrintAllMock's non-human default styling
// branch through ModeJSON (distinct from the ModePlain case already covered
// in health_mock_test.go, and exercises the msg=="" branch by using an
// inlineFn that returns "").
func TestPrintAllMockJSONMode(t *testing.T) {
	results := []runner.Result{{Name: "CPU Load"}}
	r := NewRenderer(output.ModeJSON)
	out := captureStdout(t, func() {
		r.PrintAllMock(results, nil, func(string) string { return "" })
	})
	if !strings.Contains(out, "CPU Load") {
		t.Errorf("expected row for CPU Load, got %q", out)
	}
}

// TestPrintAllMockHumanEmptyMsg covers the ModeHuman icon-only line (no
// StyleDim message suffix) — health_mock_test.go's inlineFn always returns a
// non-empty string, so the msg=="" branch under ModeHuman is otherwise unhit.
func TestPrintAllMockHumanEmptyMsg(t *testing.T) {
	results := []runner.Result{{Name: "CPU Load"}}
	r := NewRenderer(output.ModeHuman)
	out := captureStdout(t, func() {
		r.PrintAllMock(results, nil, func(string) string { return "" })
	})
	if !strings.Contains(out, "CPU Load") {
		t.Errorf("expected row for CPU Load, got %q", out)
	}
}

// TestPrintLayerHeaderNoSubtitle covers the header-without-subtitle branch.
func TestPrintLayerHeaderNoSubtitle(t *testing.T) {
	r := NewRenderer(output.ModePlain)
	out := captureStdout(t, func() { r.printLayerHeader("Other", "") })
	if !strings.Contains(out, "Other") || strings.Contains(out, "·") {
		t.Errorf("no-subtitle header should omit the separator, got %q", out)
	}
}

// TestPrintLayeredVerdictNonHuman covers the plain-text tally branch (no
// lipgloss styling call), including the INFO count (distinct from CRIT/WARN).
func TestPrintLayeredVerdictNonHuman(t *testing.T) {
	r := NewRenderer(output.ModePlain)
	out := captureStdout(t, func() {
		r.printLayeredVerdict([]models.Insight{{Level: "CRIT"}, {Level: "WARN"}, {Level: "WARN"}, {Level: "INFO"}})
	})
	if !strings.Contains(out, "1 critical · 2 warnings · 1 info") {
		t.Errorf("expected plain tally line with info count, got %q", out)
	}
}

// TestPrintLayeredVerdictHumanWarnOnly covers the WARN-styled (not CRIT)
// human-mode branch — TestPrintAllLayeredHumanMode above only exercises CRIT.
func TestPrintLayeredVerdictHumanWarnOnly(t *testing.T) {
	r := NewRenderer(output.ModeHuman)
	out := captureStdout(t, func() {
		r.printLayeredVerdict([]models.Insight{{Level: "WARN"}})
	})
	if !strings.Contains(out, "1 warnings") {
		t.Errorf("expected warn tally, got %q", out)
	}
}

// TestPrintLayeredVerdictHumanAllOK covers the human-mode all-OK branch
// (StyleOK, neither CRIT nor WARN present).
func TestPrintLayeredVerdictHumanAllOK(t *testing.T) {
	r := NewRenderer(output.ModeHuman)
	out := captureStdout(t, func() {
		r.printLayeredVerdict(nil)
	})
	if !strings.Contains(out, "0 critical · 0 warnings · 0 info") {
		t.Errorf("expected all-zero tally, got %q", out)
	}
}

// TestPrintAllLayeredOtherGroup covers the trailing "Other" section for a
// collector name not mapped to any healthLayers member.
func TestPrintAllLayeredOtherGroup(t *testing.T) {
	r := NewRenderer(output.ModePlain)
	results := []runner.Result{{Name: "TotallyUnmappedCollector"}}
	insights := []models.Insight{{Level: "WARN", Check: "TotallyUnmappedCollector", Message: "x"}}
	out := captureStdout(t, func() { r.PrintAllLayered(results, insights) })
	if !strings.Contains(out, "Other") || !strings.Contains(out, "TotallyUnmappedCollector") {
		t.Errorf("unmapped collector should surface under Other, got:\n%s", out)
	}
}

// TestPrintAllLayeredHumanMode covers the styled (ModeHuman) branches of
// printLayerHeader, printLayerNote, and printLayeredVerdict — layered_test.go
// only drives ModePlain.
func TestPrintAllLayeredHumanMode(t *testing.T) {
	r := NewRenderer(output.ModeHuman)
	results := []runner.Result{{Name: "Memory"}}
	insights := []models.Insight{{Level: "CRIT", Check: "Memory", Message: "OOM"}}
	out := captureStdout(t, func() { r.PrintAllLayered(results, insights) })
	if !strings.Contains(out, "Hardware & storage") {
		t.Errorf("expected styled layer header, got:\n%s", out)
	}
	if !strings.Contains(out, "bare metal") {
		t.Errorf("expected styled bare-metal layer note, got:\n%s", out)
	}
	if !strings.Contains(out, "1 critical") {
		t.Errorf("expected styled CRIT verdict tally, got:\n%s", out)
	}
}

// TestPrintSummaryWithElapsedTiming covers the elapsed>0 timing-suffix branch
// in the all-healthy summary path (the exit-code smoke tests always pass 0).
func TestPrintSummaryWithElapsedTiming(t *testing.T) {
	r := NewRenderer(output.ModeHuman)
	out := captureStdout(t, func() { r.PrintSummary(nil, 2500000000) }) // 2.5s in ns
	if !strings.Contains(out, "in 2.5s") {
		t.Errorf("expected elapsed timing suffix, got %q", out)
	}
}

// TestPrintSummaryPlainHealthy covers the non-human "OK: All checks passed"
// wording branch (distinct from the styled human branch).
func TestPrintSummaryPlainHealthy(t *testing.T) {
	r := NewRenderer(output.ModePlain)
	out := captureStdout(t, func() { r.PrintSummary(nil, 0) })
	if !strings.Contains(out, "OK: All checks passed") {
		t.Errorf("expected plain healthy wording, got %q", out)
	}
}

// TestPrintSummaryWithInfoInsight covers the INFO-level bucketing branch
// alongside a CRIT/WARN insight.
func TestPrintSummaryWithInfoInsight(t *testing.T) {
	r := NewRenderer(output.ModeHuman)
	insights := []models.Insight{
		{Level: "CRIT", Check: "Disk", Message: "full"},
		{Level: "INFO", Check: "Drives", Message: "5 power-on years"},
	}
	out := captureStdout(t, func() { r.PrintSummary(insights, 0) })
	if !strings.Contains(out, "power-on years") {
		t.Errorf("expected INFO insight rendered in summary, got %q", out)
	}
}

// TestPrintSummaryInfoOnlyNotDropped guards against the false-clean renderer
// bug: a run with zero CRIT/WARN still prints the healthy line (the verdict IS
// clean), but must NOT silently drop INFO-level disclosures such as "could not
// measure" insights just because the top-line verdict short-circuits first.
func TestPrintSummaryInfoOnlyNotDropped(t *testing.T) {
	r := NewRenderer(output.ModeHuman)
	insights := []models.Insight{
		{Level: "INFO", Check: "Memory", Message: "RAM usage check skipped — cgroup memory usage could not be read"},
	}
	out := captureStdout(t, func() { r.PrintSummary(insights, 0) })
	if !strings.Contains(out, "System healthy") {
		t.Errorf("expected the healthy line (no CRIT/WARN present), got %q", out)
	}
	if !strings.Contains(out, "RAM usage check skipped") {
		t.Errorf("INFO-only insight must still be printed, not dropped by the healthy short-circuit, got %q", out)
	}
}
