package render

import (
	"fmt"
	"io"
	"regexp"
	"sort"

	"github.com/keyorixhq/dashdiag/internal/models"
	"github.com/keyorixhq/dashdiag/internal/output"
)

// watchdiff powers the "Changes since last refresh" block in `dsd health --watch`.
// Between ticks we surface what is newly broken, newly resolved, or changed
// severity — so an operator watching an incident sees the delta, not the whole
// board re-read each cycle.

// digitRun collapses any number (incl. decimals/percentages) so a verdict whose
// only difference between ticks is a fluctuating value (CPU 75% → 82%) is treated
// as the same underlying issue, not a churn of resolved+new every refresh.
var digitRun = regexp.MustCompile(`\d+(\.\d+)?`)

// insightSignature is a tick-stable identity for an insight: its check plus its
// message with numbers normalized away. Severity is deliberately excluded so a
// WARN→CRIT escalation matches the same signature and reports as a change, not a
// resolve+new pair.
func insightSignature(ins models.Insight) string {
	return ins.Check + "|" + digitRun.ReplaceAllString(ins.Message, "#")
}

// InsightChange is an insight whose severity changed between two ticks.
type InsightChange struct {
	Insight   models.Insight // the current-tick insight (latest message)
	FromLevel string
	ToLevel   string
}

// InsightChanges diffs two ticks' insights by signature, returning what appeared
// (added), what disappeared (resolved), and what changed severity (changed).
// INFO/OK-level entries are included — surfacing a CRIT→INFO de-escalation is the
// whole point. Results are stable-ordered for deterministic rendering.
func InsightChanges(prev, cur []models.Insight) (added, resolved []models.Insight, changed []InsightChange) {
	prevBySig := make(map[string]models.Insight, len(prev))
	for _, ins := range prev {
		prevBySig[insightSignature(ins)] = ins
	}
	curBySig := make(map[string]models.Insight, len(cur))
	for _, ins := range cur {
		sig := insightSignature(ins)
		curBySig[sig] = ins
		p, seen := prevBySig[sig]
		switch {
		case !seen:
			added = append(added, ins)
		case p.Level != ins.Level:
			changed = append(changed, InsightChange{Insight: ins, FromLevel: p.Level, ToLevel: ins.Level})
		}
	}
	for _, ins := range prev {
		if _, seen := curBySig[insightSignature(ins)]; !seen {
			resolved = append(resolved, ins)
		}
	}
	sortInsights(added)
	sortInsights(resolved)
	sort.SliceStable(changed, func(i, j int) bool {
		return changed[i].Insight.Check < changed[j].Insight.Check
	})
	return added, resolved, changed
}

// sortInsights orders by severity (CRIT first) then check, for stable output.
func sortInsights(in []models.Insight) {
	sort.SliceStable(in, func(i, j int) bool {
		ri, rj := severityRank(in[i].Level), severityRank(in[j].Level)
		if ri != rj {
			return ri > rj
		}
		return in[i].Check < in[j].Check
	})
}

func severityRank(level string) int {
	switch level {
	case "CRIT":
		return 3
	case "WARN":
		return 2
	case "INFO":
		return 1
	default:
		return 0
	}
}

// PrintInsightChanges writes the "Changes since last refresh" block. When nothing
// changed it prints a single dim "no change" line — a useful steady-state signal
// while watching. It renders for the human-readable text modes (human + plain) and
// is a no-op for structured output (JSON/YAML/report), which emit the board only.
func PrintInsightChanges(w io.Writer, added, resolved []models.Insight, changed []InsightChange, mode output.OutputMode) {
	if mode != output.ModeHuman && mode != output.ModePlain {
		return
	}
	fmt.Fprintln(w)
	fmt.Fprintln(w, StyleBold.Render("Changes since last refresh"))
	if len(added) == 0 && len(resolved) == 0 && len(changed) == 0 {
		fmt.Fprintln(w, StyleDim.Render("  · no change"))
		return
	}
	for _, ins := range added {
		st := styleForStatus(ins.Level)
		fmt.Fprintf(w, "  %s %s %s: %s\n", st.Render("🆕"), st.Render(ins.Level), ins.Check, ins.Message)
	}
	for _, c := range changed {
		arrow := fmt.Sprintf("%s→%s", c.FromLevel, c.ToLevel)
		st := styleForStatus(c.ToLevel)
		fmt.Fprintf(w, "  %s %s %s: %s\n", st.Render("↕"), st.Render(arrow), c.Insight.Check, c.Insight.Message)
	}
	for _, ins := range resolved {
		fmt.Fprintf(w, "  %s %s %s: %s\n", StyleOK.Render("✅"), StyleOK.Render("resolved"), ins.Check, StyleDim.Render(ins.Message))
	}
}
