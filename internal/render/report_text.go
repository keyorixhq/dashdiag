package render

import (
	"fmt"
	"sort"
	"strings"
)

// RenderReportText renders a decoded JSONOutput (from a `dsd health --blob`
// share blob) as a plain-text diagnosis. Plain text — no colour/TUI — so it is
// readable wherever support pastes it. It reproduces the verdict, the insights
// grouped worst-first, and a one-line check tally; the heavy per-check `raw`
// data stays in the blob's JSON (use `dsd decode --json` for that).
func RenderReportText(o JSONOutput) string {
	var b strings.Builder

	fmt.Fprintf(&b, "DashDiag report — %s · %s\n", orDash(o.Hostname), orDash(o.OS))
	fmt.Fprintf(&b, "captured %s · dsd %s\n\n", o.Timestamp.Format("2006-01-02 15:04:05 MST"), orDash(o.Version))

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

	if len(ins) == 0 {
		b.WriteString("\nNo findings — all checks reported OK.\n")
	} else {
		b.WriteString("\n")
		for _, in := range ins {
			fmt.Fprintf(&b, "[%s] %s: %s\n", in.Level, in.Check, in.Message)
			for _, h := range in.Hints {
				fmt.Fprintf(&b, "   -> %s\n", h)
			}
		}
	}

	// Errored checks are worth surfacing — a collector that failed to run is a
	// gap in the diagnosis, not a clean result.
	var errored []string
	for _, c := range o.Checks {
		if c.Status == "ERROR" {
			errored = append(errored, c.Name)
		}
	}
	if len(errored) > 0 {
		sort.Strings(errored)
		fmt.Fprintf(&b, "\nChecks that errored (incomplete data): %s\n", strings.Join(errored, ", "))
	}

	return b.String()
}

func orDash(s string) string {
	if s == "" {
		return "—"
	}
	return s
}
