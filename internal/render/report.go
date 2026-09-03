package render

import (
	"fmt"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/keyorixhq/dashdiag/internal/baseline"
	"github.com/keyorixhq/dashdiag/internal/models"
	"github.com/keyorixhq/dashdiag/internal/output"
	"github.com/keyorixhq/dashdiag/internal/version"
)

// GenerateReport produces a markdown health report and writes it to a file.
// Returns the output file path.
func GenerateReport(snap *baseline.Snapshot, insights []models.Insight, elapsed time.Duration, cve *models.CVEAllResult) (string, error) {
	if snap == nil {
		return "", fmt.Errorf("no snapshot data")
	}

	md := buildMarkdown(snap, insights, elapsed, cve)

	timestamp := snap.Timestamp.Format("20060102-150405")
	// snap.Hostname is attacker-controlled during `dsd replay <bundle> --report`
	// (it comes from the bundle manifest's Host field, read with no validation) —
	// sanitize before it reaches a filename, same as baseline.SafeHostname's own
	// doc comment names this threat.
	filename := fmt.Sprintf("dsd-report-%s-%s.md", baseline.SafeHostname(snap.Hostname), timestamp)
	path := filepath.Join(".", filename)

	if err := writeReportFileNoFollow(path, []byte(md), 0o644); err != nil { //nolint:gosec // report file, world-readable intentional
		return "", fmt.Errorf("writing report: %w", err)
	}
	return path, nil
}

func buildMarkdown(snap *baseline.Snapshot, insights []models.Insight, elapsed time.Duration, cve *models.CVEAllResult) string { //nolint:funlen // report renderer — each section is a distinct block
	var b strings.Builder

	crits := countLevel(insights, "CRIT")
	warns := countLevel(insights, "WARN")
	total := crits + warns

	// Header
	fmt.Fprintf(&b, "# DashDiag Health Report\n\n")
	fmt.Fprintf(&b, "**Host:** `%s`  \n", output.SanitizeControl(snap.Hostname))
	fmt.Fprintf(&b, "**Date:** %s  \n", snap.Timestamp.Format("2006-01-02 15:04:05 MST"))
	fmt.Fprintf(&b, "**Scan time:** %.1fs  \n", elapsed.Seconds())
	fmt.Fprintf(&b, "**Version:** %s  \n\n", version.Version)

	// Summary
	fmt.Fprintf(&b, "## Summary\n\n")
	if total == 0 {
		fmt.Fprintf(&b, "✅ **All checks passed** — system is healthy.\n\n")
	} else {
		if crits > 0 {
			fmt.Fprintf(&b, "🔴 **%d critical** issue(s) require immediate attention.  \n", crits)
		}
		if warns > 0 {
			fmt.Fprintf(&b, "⚠️  **%d warning(s)** found.  \n", warns)
		}
		fmt.Fprintf(&b, "\n")
	}

	// Issues — CRIT first, then WARN, then INFO disclosures (a collector that
	// errored, an unmeasurable value, etc.). INFO isn't a pass/fail verdict
	// change (kept out of the Summary's healthy/not-healthy line above, same as
	// PrintSummary in health.go), but it must never be silently dropped from
	// the report the way it used to be — a check that completely failed to run
	// showed as "✅ OK" here with zero trace anywhere in the document.
	actionable := filterActionable(insights)
	if len(actionable) > 0 {
		fmt.Fprintf(&b, "## Issues\n\n")
		for _, ins := range actionable {
			icon := "⚠️"
			switch ins.Level {
			case "CRIT":
				icon = "🔴"
			case "INFO":
				icon = "ℹ️"
			}
			fmt.Fprintf(&b, "### %s %s — %s\n\n", icon, ins.Level, output.SanitizeControl(ins.Check))
			// ins.Message can carry attacker-controlled substrings (e.g. a
			// process name a local user set via prctl(PR_SET_NAME), surfaced
			// through an FD-limit or similar heuristic) — markdown doesn't
			// escape raw control/ANSI bytes any more than a terminal does, and
			// this report is explicitly designed to be pasted into incident
			// channels/tickets, so strip them the same way every other
			// rendered sink in this codebase does.
			fmt.Fprintf(&b, "%s\n\n", output.SanitizeControl(ins.Message))
			if len(ins.Hints) > 0 {
				// One fenced block for ALL remediation lines — a separate fence per
				// line renders as a stack of tiny code boxes, which looks broken in a
				// client-facing report.
				fmt.Fprintf(&b, "**Remediation:**\n\n```\n")
				for _, h := range ins.Hints {
					// output.SanitizeControl strips control/ANSI bytes but does
					// nothing about literal backticks — a Hint containing a run
					// of 3+ backticks could otherwise close this fence early and
					// inject arbitrary markdown/HTML into the rest of the
					// generated report (internal-render-03-05). Neutralize
					// backticks with the same helper postmortem.go's inline
					// `%s` spans use, since both are "text this codebase didn't
					// author reaching a backtick-delimited markdown construct".
					fmt.Fprintf(&b, "%s\n", escapeMarkdownBackticks(output.SanitizeControl(h)))
				}
				fmt.Fprintf(&b, "```\n\n")
			}
		}
	}

	// Check results table
	fmt.Fprintf(&b, "## Check Results\n\n")
	fmt.Fprintf(&b, "| Check | Status |\n")
	fmt.Fprintf(&b, "|---|---|\n")

	// Per-check status comes straight from the snapshot. baseline.BuildSnapshot
	// already records each check's WORST finding and rolls a subsystem-qualified
	// insight ("Network/DNS", "Memory/Slab") up to its collector ("Network",
	// "Memory"). Re-deriving status here from the raw insights — which were keyed by
	// the *qualified* Check name yet looked up by the *base* collector name — dropped
	// a DNS-only CRIT: the table showed "Network ✅ OK" while the Issues section above
	// listed that very CRIT (a false-OK in --report). Trust the snapshot's status.
	//
	// Deterministic, worst-first order: snap.Checks comes back in map/iteration
	// order (different every run, which reads as unstable in a client report).
	// Sort CRIT → WARN → INFO → OK, alphabetical within each rank. INFO covers
	// a collector that errored (or an unmeasurable value) — check.Status is set
	// from the snapshot's worst insight (baseline.BuildSnapshot), so it's never
	// anything the switch below doesn't already name; the explicit "default"
	// case is reserved for the real OK/absent-insight case, not as a catch-all
	// for statuses this switch forgot (guarded repo-wide by
	// status_switch_governance_test.go's TestNoStatusSwitchSwallowsALevel).
	type checkRow struct {
		name, status string
		rank         int
	}
	rows := make([]checkRow, 0, len(snap.Checks))
	for _, check := range snap.Checks {
		name := output.SanitizeControl(check.Name)
		switch check.Status {
		case "CRIT":
			rows = append(rows, checkRow{name, "🔴 CRIT", 3})
		case "WARN":
			rows = append(rows, checkRow{name, "⚠️ WARN", 2})
		case "INFO":
			rows = append(rows, checkRow{name, "ℹ️ INFO", 1})
		default:
			rows = append(rows, checkRow{name, "✅ OK", 0})
		}
	}
	sort.Slice(rows, func(i, j int) bool {
		if rows[i].rank != rows[j].rank {
			return rows[i].rank > rows[j].rank
		}
		return rows[i].name < rows[j].name
	})
	for _, r := range rows {
		fmt.Fprintf(&b, "| %s | %s |\n", r.name, r.status)
	}
	fmt.Fprintf(&b, "\n")

	// CVE section (populated when --report is run with CVE data)
	if cve != nil && cve.PackageManager != "" {
		total := len(cve.Critical) + len(cve.Important) + len(cve.Moderate) + len(cve.Low)
		fmt.Fprintf(&b, "## Security Advisories\n\n")
		if total == 0 {
			fmt.Fprintf(&b, "✅ No pending security advisories.\n\n")
		} else {
			fmt.Fprintf(&b, "**%d pending security advisor%s** (via %s)\n\n",
				total, pluralY(total), cve.PackageManager)
			if len(cve.Critical) > 0 {
				fmt.Fprintf(&b, "### 🔴 Critical (%d)\n\n", len(cve.Critical))
				for _, a := range cve.Critical {
					fmt.Fprintf(&b, "- `%s` — %s\n", a.ID, a.Summary)
				}
				fmt.Fprintf(&b, "\n")
			}
			if len(cve.Important) > 0 {
				fmt.Fprintf(&b, "### ⚠️  Important (%d)\n\n", len(cve.Important))
				for _, a := range cve.Important {
					fmt.Fprintf(&b, "- `%s` — %s\n", a.ID, a.Summary)
				}
				fmt.Fprintf(&b, "\n")
			}
			if len(cve.Moderate) > 0 {
				fmt.Fprintf(&b, "### Moderate (%d)\n\n", len(cve.Moderate))
				for _, a := range cve.Moderate {
					fmt.Fprintf(&b, "- `%s` — %s\n", a.ID, a.Summary)
				}
				fmt.Fprintf(&b, "\n")
			}
			if len(cve.Low) > 0 {
				fmt.Fprintf(&b, "### Low (%d)\n\n", len(cve.Low))
				for _, a := range cve.Low {
					fmt.Fprintf(&b, "- `%s` — %s\n", a.ID, a.Summary)
				}
				fmt.Fprintf(&b, "\n")
			}
			fmt.Fprintf(&b, "To fix all: `%s`\n\n", cve.FixCommand)
		}
	}

	// Footer
	fmt.Fprintf(&b, "---\n")
	fmt.Fprintf(&b, "*Generated by [DashDiag](https://github.com/keyorixhq/dashdiag) %s — [dashdiag.sh](https://dashdiag.sh)*\n",
		version.Version)

	return b.String()
}

func pluralY(n int) string {
	if n == 1 {
		return "y"
	}
	return "ies"
}

// filterActionable returns the insights worth surfacing in a report's Issues
// section: CRIT/WARN findings plus INFO disclosures (collector errors,
// unmeasurable values) — everything except a plain OK. Shared by the markdown
// and HTML report renderers.
func filterActionable(insights []models.Insight) []models.Insight {
	rank := map[string]int{"CRIT": 0, "WARN": 1, "INFO": 2}
	var out []models.Insight
	for _, ins := range insights {
		if _, ok := rank[ins.Level]; ok {
			out = append(out, ins)
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Level != out[j].Level {
			return rank[out[i].Level] < rank[out[j].Level]
		}
		return out[i].Check < out[j].Check
	})
	return out
}

func countLevel(insights []models.Insight, level string) int {
	n := 0
	for _, ins := range insights {
		if ins.Level == level {
			n++
		}
	}
	return n
}

// escapeMarkdownBackticks neutralizes literal backtick characters in
// attacker-influenced text (an Insight's Message/Hints, a check's
// Name/Value) before it is embedded inside a markdown backtick-delimited
// construct. Two distinct backtick-delimited constructs are affected across
// this package: a fenced ``` code block (report.go's Remediation block) can
// be closed early by a run of 3+ backticks in the content
// (internal-render-03-05), and a single-backtick inline code span
// (postmortem.go's `%s` remediation steps) is closed by even ONE embedded
// backtick (internal-render-03-06). Rather than tracking run-lengths per
// call site, replace every backtick unconditionally with a visually similar
// substitute (U+02CB MODIFIER LETTER GRAVE ACCENT) — this satisfies both
// constructs at once (zero backticks reach either sink) and keeps the text
// legible, unlike dropping the character outright. Shared by report.go and
// postmortem.go rather than duplicated — same package, no import needed.
func escapeMarkdownBackticks(s string) string {
	return strings.ReplaceAll(s, "`", "ˋ")
}
