package render

import (
	"fmt"
	"sort"
	"strings"

	"github.com/keyorixhq/dashdiag/internal/models"
	"github.com/keyorixhq/dashdiag/internal/output"
)

// RenderReportText renders a decoded JSONOutput (from a `dsd health --blob`
// share blob) as a plain-text diagnosis. Plain text — no colour/TUI — so it is
// readable wherever support pastes it. It reproduces the verdict, the insights
// grouped worst-first, and a one-line check tally; the heavy per-check `raw`
// data stays in the blob's JSON (use `dsd decode --json` for that).
func RenderReportText(o JSONOutput) string {
	var b strings.Builder

	fmt.Fprintf(&b, "DashDiag report — %s · %s\n", orDash(output.SanitizeControl(o.Hostname)), orDash(output.SanitizeControl(o.OS)))
	fmt.Fprintf(&b, "captured %s · dsd %s\n\n", o.Timestamp.Format("2006-01-02 15:04:05 MST"), orDash(output.SanitizeControl(o.Version)))

	fmt.Fprintf(&b, "VERDICT: %s   (%d CRIT, %d WARN, %d INFO across %d checks)\n",
		orDash(o.Verdict), o.Counts.Crit, o.Counts.Warn, o.Counts.Info, len(o.Checks))

	// Insights worst-first (CRIT, WARN, INFO), then by check name for stability.
	ins := make([]JSONInsight, len(o.Insights))
	copy(ins, o.Insights)
	sort.SliceStable(ins, func(i, j int) bool {
		si, sj := severityOrder(ins[i].Level), severityOrder(ins[j].Level)
		if si != sj {
			return si > sj
		}
		return ins[i].Check < ins[j].Check
	})

	switch {
	case len(ins) == 0 && o.Coverage.NotChecked > 0:
		b.WriteString("\nNo findings, but not everything was checked — see Coverage below.\n")
	case len(ins) == 0:
		b.WriteString("\nNo findings — all checks reported OK.\n")
	default:
		b.WriteString("\n")
		for _, in := range ins {
			fmt.Fprintf(&b, "[%s] %s: %s\n", in.Level, output.SanitizeControl(in.Check), output.SanitizeControl(in.Message))
			for _, h := range in.Hints {
				fmt.Fprintf(&b, "   -> %s\n", output.SanitizeControl(h))
			}
		}
	}

	// Errored checks are worth surfacing — a collector that failed to run is a
	// gap in the diagnosis, not a clean result.
	var errored []string
	for _, c := range o.Checks {
		if c.Status == "ERROR" {
			errored = append(errored, output.SanitizeControl(c.Name))
		}
	}
	if len(errored) > 0 {
		sort.Strings(errored)
		fmt.Fprintf(&b, "\nChecks that errored (incomplete data): %s\n", strings.Join(errored, ", "))
	}

	// Root-only reads a non-root run could not do: shown, and the verdict above is
	// still OK, so the report must say what was not looked at.
	skipped := map[string]struct{}{}
	for _, in := range o.Insights {
		if in.Unverified && in.NeedsRoot {
			skipped[in.Check] = struct{}{}
		}
	}
	if n := len(skipped); n > 0 {
		unit := "checks"
		if n == 1 {
			unit = "check"
		}
		fmt.Fprintf(&b, "\nneeds root: %d %s skipped — re-run with sudo\n", n, unit)
	}

	writeCoverageText(&b, o)

	return b.String()
}

// writeCoverageText prints the blob's coverage: the summary line and what was
// not looked at. A blob from a dsd that predates coverage has none, and prints
// nothing here.
func writeCoverageText(b *strings.Builder, o JSONOutput) {
	c := o.Coverage
	if c.Checked == 0 && c.NotChecked == 0 && c.NotApplicable == 0 {
		return
	}
	sum := models.CoverageSummary{Checked: c.Checked, NotChecked: c.NotChecked, NotApplicable: c.NotApplicable, Reasons: c.NotCheckedReasons}
	for _, ck := range o.Checks {
		sum.Checks = append(sum.Checks, models.CheckCoverage{
			Name: ck.Name, Coverage: ck.Coverage, Reason: ck.CoverageReason, NotCheckedSubchecks: ck.NotCheckedSubchecks,
		})
	}
	fmt.Fprintf(b, "\nCoverage: %s\n", CoverageLine(&sum))
	for _, it := range NotCheckedItems(&sum) {
		line := fmt.Sprintf("  not checked: %s — %s", output.SanitizeControl(it.Check), strings.ReplaceAll(it.Reason, "_", " "))
		if act := it.Action(); act != "" {
			line += " — " + act
		}
		fmt.Fprintln(b, line)
	}
}

func orDash(s string) string {
	if s == "" {
		return "—"
	}
	return s
}

// decodeAuthenticityCheck is the Check/category name for
// WithDecodeDisclosure's synthetic insight — not tied to any collector, so
// it uses a category name of its own rather than borrowing one.
const decodeAuthenticityCheck = "Decode"

// WithDecodeDisclosure returns a copy of o with an INFO-level insight
// prepended to Insights (and Counts.Info incremented to match) disclosing
// that the report's authenticity was never verified.
//
// internal-share-01-02: share.Decode only checks that a pasted blob is
// well-formed (base64 decodes, gzip CRC checks out) — it has no signature or
// other binding to the host that supposedly produced it, so a hand-crafted
// blob renders identically to a genuine one. `dsd decode`'s two output
// paths — this one (feeding RenderReportText) and --json (which marshals
// the same o) — both call this before doing anything else with the decoded
// report, so the disclosure reaches both, not just whichever a human happens
// to be looking at. Uses the existing INFO-level insight shape (an already
// schema-valid enum value, see schema/dsd-output.json's insights[].level) —
// no new severity level, matching the frozen 1.x insights[].level contract.
func WithDecodeDisclosure(o JSONOutput) JSONOutput {
	note := JSONInsight{
		Check: decodeAuthenticityCheck,
		Level: "INFO",
		Message: "This report's authenticity is not verified — a dsd health --blob block has no " +
			"signature binding it to the host that produced it, and dsd decode only checks that " +
			"it is well-formed, not who created it.",
		Hints: []string{"treat a decoded report like any other pasted text — verify out of band before acting on it"},
	}
	o.Insights = append([]JSONInsight{note}, o.Insights...)
	o.Counts.Info++
	return o
}
