package render

// topcatch.go — the "Top catch" line: the single most salient finding from a
// run, printed after the health table and before the summary (`dsd health`,
// `dsd demo`), right under the verdict line (`dsd share --format text`), and
// as an additive `top_catch` field on the standard JSON output (`dsd health
// --json`, `dsd demo --json`, `dsd share --json`, the `dsd_health` MCP tool).
//
// Selection order: highest severity first (CRIT beats WARN); among ties, a
// correlated root cause beats a lone symptom insight (analysis.Correlate
// already explains WHY several signals fired together — that's more useful
// than picking one of the symptoms it covers); among ties with no
// correlation, an insight with a fix hint beats one without; remaining ties
// break alphabetically by check name for run-to-run determinism.

import (
	"fmt"
	"os"
	"strings"

	"github.com/keyorixhq/dashdiag/internal/analysis"
	"github.com/keyorixhq/dashdiag/internal/models"
	"github.com/keyorixhq/dashdiag/internal/output"
)

// TopCatch is the single most salient finding this run — see ComputeTopCatch.
type TopCatch struct {
	Topic    string `json:"topic"`
	Severity string `json:"severity"`
	Summary  string `json:"summary"`
	Fix      string `json:"fix"`
}

// topCatchSeverityOrder ranks the two levels a Correlation or an actionable
// Insight can carry — INFO/OK never produce a Top catch (see the "verdict is
// OK" case: the all-clear line is printed separately by the caller).
var topCatchSeverityOrder = map[string]int{"CRIT": 2, "WARN": 1}

// topCatchFallbackFix is used when the winning insight has no Hints — always
// a valid, safe command (the --explain flag already exists on `dsd health`),
// so the line is never left with an empty "→ " tail.
const topCatchFallbackFix = "dsd health --explain"

// ComputeTopCatch returns the single most salient finding, or nil when there
// is no CRIT/WARN this run (an all-clear or INFO-only run — the caller
// prints "Top catch: none — N checks passed." for that case instead).
func ComputeTopCatch(insights []models.Insight, corrs []analysis.Correlation) *TopCatch {
	maxSev := 0
	for _, ins := range insights {
		if v := topCatchSeverityOrder[ins.Level]; v > maxSev {
			maxSev = v
		}
	}
	for _, c := range corrs {
		if v := topCatchSeverityOrder[c.Level]; v > maxSev {
			maxSev = v
		}
	}
	if maxSev == 0 {
		return nil
	}
	sevName := "WARN"
	if maxSev == 2 {
		sevName = "CRIT"
	}

	// A correlated root cause at the top severity always wins over a lone
	// symptom insight, even a symptom at the same severity — see the file
	// doc comment. corrs is produced in a fixed rule-evaluation order
	// (analysis.Correlate/CorrelateDeep), so taking the first match at
	// maxSev is a deterministic tie-break, not an arbitrary one.
	for i := range corrs {
		c := corrs[i]
		if topCatchSeverityOrder[c.Level] != maxSev {
			continue
		}
		topic := ""
		if len(c.Checks) > 0 {
			topic = checkSlug(c.Checks[0])
		}
		return &TopCatch{Topic: topic, Severity: sevName, Summary: c.Summary, Fix: c.Action}
	}

	// No correlation explains the top severity — pick among the raw
	// insights at that level: a fix beats no fix, then alphabetical by
	// Check for determinism.
	var best *models.Insight
	for i := range insights {
		ins := &insights[i]
		if topCatchSeverityOrder[ins.Level] != maxSev {
			continue
		}
		if best == nil {
			best = ins
			continue
		}
		bestHasFix := len(best.Hints) > 0
		insHasFix := len(ins.Hints) > 0
		if insHasFix != bestHasFix {
			if insHasFix {
				best = ins
			}
			continue
		}
		if ins.Check < best.Check {
			best = ins
		}
	}
	if best == nil {
		// Unreachable: maxSev > 0 means either the correlation loop above
		// already returned, or at least one insight is at maxSev.
		return nil
	}

	fix := topCatchFallbackFix
	if len(best.Hints) > 0 {
		fix = best.Hints[0]
	}
	return &TopCatch{Topic: checkSlug(best.Check), Severity: sevName, Summary: best.Message, Fix: fix}
}

// TopCatchLine computes the Top catch line for a non-JSON rendered report
// (markdown, HTML, the share text form), using insights-only correlation
// (analysis.Correlate — no raw collector models available to these
// renderers). Topic/Summary/Fix are sanitized for a rendered sink; ok is
// false when there's no CRIT/WARN this run, in which case the caller should
// print the "none — N checks passed" form instead.
func TopCatchLine(insights []models.Insight) (tc *TopCatch, ok bool) {
	t := ComputeTopCatch(insights, analysis.Correlate(insights))
	if t == nil {
		return nil, false
	}
	return &TopCatch{
		Topic:    t.Topic,
		Severity: t.Severity,
		Summary:  output.SanitizeControl(t.Summary),
		Fix:      output.SanitizeControl(t.Fix),
	}, true
}

// writeTopCatchMarkdown appends the Top catch line to a markdown report
// body, used by both GenerateReport (`dsd health --report`) and `dsd share
// --format md` (which redacts the same body afterward).
func writeTopCatchMarkdown(b *strings.Builder, insights []models.Insight, checksTotal int) {
	tc, ok := TopCatchLine(insights)
	if !ok {
		fmt.Fprintf(b, "**Top catch:** none — %d checks passed.\n\n", checksTotal)
		return
	}
	fmt.Fprintf(b, "**Top catch:** %s (`%s`) → %s\n\n",
		escapeMarkdownBackticks(tc.Summary), tc.Topic, escapeMarkdownBackticks(tc.Fix))
}

// PrintTopCatch prints the single Top catch line — the highest-severity
// finding, a correlated root cause preferred over a lone symptom — or an
// all-clear line when there's no CRIT/WARN this run. checksTotal is only
// used in that all-clear line ("Top catch: none — N checks passed.").
// No-ops in JSON/YAML mode — those get the additive top_catch field on
// JSONOutput instead (see ComputeTopCatch, called from buildOutput).
func (r *Renderer) PrintTopCatch(insights []models.Insight, corrs []analysis.Correlation, checksTotal int) {
	if r.mode == output.ModeJSON || r.mode == output.ModeYAML {
		return
	}
	tc := ComputeTopCatch(insights, corrs)
	if tc == nil {
		fmt.Fprintf(os.Stdout, "Top catch: none — %d checks passed.\n", checksTotal)
		return
	}
	// Topic/Summary/Fix are derived from Correlation.Summary/Action or
	// Insight.Message/Hints — collector-sourced text that can carry
	// attacker-influenced substrings, same as every other terminal-print
	// boundary in this file (printInsightGroup, PrintCorrelations).
	topic := output.SanitizeControl(tc.Topic)
	summary := output.SanitizeControl(tc.Summary)
	fix := output.SanitizeControl(tc.Fix)
	line := fmt.Sprintf("Top catch: %s (%s) → %s", summary, topic, fix)
	if r.mode == output.ModeHuman {
		fmt.Fprintln(os.Stdout, styleForStatus(tc.Severity).Render(line))
	} else {
		fmt.Fprintln(os.Stdout, line)
	}
}
