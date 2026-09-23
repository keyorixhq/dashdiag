package render

// sharetext.go — the short "text" format behind `dsd share --format text`: a
// ticket-pasteable summary capped at a handful of lines, unlike the full
// markdown/HTML reports. See docs/SHARE_DESIGN.md's "Local share (shipped)"
// section.

import (
	"fmt"
	"strings"

	"github.com/keyorixhq/dashdiag/internal/baseline"
	"github.com/keyorixhq/dashdiag/internal/models"
	"github.com/keyorixhq/dashdiag/internal/output"
	"github.com/keyorixhq/dashdiag/internal/version"
)

// maxShareTextFindings caps how many findings are listed before the text
// format truncates with a "N more omitted" line — the ≤40-line budget holds
// for any real host (header/verdict/footer cost ~6 lines) even when a run
// surfaces dozens of findings.
const maxShareTextFindings = 30

// RenderShareText builds the short ticket-form summary for `dsd share
// --format text`: host + OS + dsd version, a one-line verdict, then every
// actionable finding (CRIT/WARN/INFO) worst-first as a single line with its
// checks-catalog link, and the footer. osLabel may be empty when the source
// (a bare snapshot.json, with no OS field) doesn't carry one — the line is
// omitted rather than showing a placeholder.
func RenderShareText(snap *baseline.Snapshot, insights []models.Insight, osLabel string) string {
	var b strings.Builder

	head := []string{output.SanitizeControl(snap.Hostname)}
	if osLabel != "" {
		head = append(head, output.SanitizeControl(osLabel))
	}
	head = append(head, "dsd "+version.Version)
	fmt.Fprintf(&b, "%s\n", strings.Join(head, " · "))
	fmt.Fprintf(&b, "%s\n\n", snap.Timestamp.Format("2006-01-02 15:04:05 MST"))

	crit := countLevel(insights, "CRIT")
	warn := countLevel(insights, "WARN")
	switch {
	case crit > 0:
		fmt.Fprintf(&b, "Verdict: CRIT — %d critical, %d warning\n", crit, warn)
	case warn > 0:
		fmt.Fprintf(&b, "Verdict: WARN — %d warning\n", warn)
	default:
		fmt.Fprintf(&b, "Verdict: OK — all checks passed\n")
	}
	if tc, ok := TopCatchLine(insights); ok {
		fmt.Fprintf(&b, "Top catch: %s (%s) → %s\n\n", tc.Summary, tc.Topic, tc.Fix)
	} else {
		fmt.Fprintf(&b, "Top catch: none — %d checks passed.\n\n", len(snap.Checks))
	}

	findings := filterActionable(insights)
	shown, omitted := findings, 0
	if len(shown) > maxShareTextFindings {
		omitted = len(shown) - maxShareTextFindings
		shown = shown[:maxShareTextFindings]
	}
	for _, ins := range shown {
		fmt.Fprintln(&b, shareTextFindingLine(ins))
	}
	if omitted > 0 {
		fmt.Fprintf(&b, "… %d more finding(s) omitted — see the full report: dsd share --format md\n", omitted)
	}

	fmt.Fprintf(&b, "\n— dsd %s · https://github.com/keyorixhq/dashdiag · https://dashdiag.sh/?src=share\n", version.Version)
	return b.String()
}

// shareTextFindingLine renders one finding as `[LEVEL] check-id — message →
// fix: <cmd> (catalog-url)`, all on one line so the ≤40-line budget holds
// regardless of finding count.
func shareTextFindingLine(ins models.Insight) string {
	line := fmt.Sprintf("[%s] %s — %s", ins.Level, checkSlug(ins.Check), output.SanitizeControl(ins.Message))
	if len(ins.Hints) > 0 {
		line += " → fix: " + output.SanitizeControl(ins.Hints[0])
	}
	return line + " (" + checkURL(ins.Check) + ")"
}
