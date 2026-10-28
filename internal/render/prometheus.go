package render

import (
	"fmt"
	"strings"

	"github.com/keyorixhq/dashdiag/internal/models"
	"github.com/keyorixhq/dashdiag/internal/runner"
)

// PrometheusMetrics renders the health verdict in the Prometheus text exposition
// format for `dsd health --prometheus` — drop the output into node_exporter's
// textfile collector (or scrape it) to chart and alert on host health in
// Grafana/Alertmanager. Three metrics:
//
//	dsd_up                       1 when the scan completed
//	dsd_check_status{check="x"}  per-subsystem severity (0=OK, 1=WARN, 2=CRIT)
//	dsd_health_status            worst severity across all checks
//
// Severity is the same 0/1/2 scale as dsd's exit code (INFO counts as OK, but a
// check that could not run or be verified counts as WARN — C1). A
// per-check series is emitted for every subsystem that actually ran, so a check
// flipping OK→WARN is a value change, not a series appearing/disappearing.
func PrometheusMetrics(results []runner.Result, insights []models.Insight) string {
	worstByCheck := map[string]int{}
	for _, ins := range insights {
		v := promSeverity(ins.Level)
		// C1: a check that could not be verified is not "0=OK": floor it at WARN,
		// the same floor the JSON verdict and the exit code apply.
		if ins.Unverified && !ins.NeedsRoot && v < 1 {
			v = 1
		}
		// Roll a subsystem-qualified Check ("Network/DNS", "Memory/Slab",
		// "CPU Load/Steal") up to its base collector name ("Network", "Memory",
		// "CPU Load"), since the per-check series below is keyed by collector name.
		// Without this a DNS-only CRIT left dsd_check_status{check="network"} at 0
		// while dsd_health_status was 2 — the per-check metric hid the cause.
		base := ins.Check
		if i := strings.IndexByte(base, '/'); i >= 0 {
			base = base[:i]
		}
		if v > worstByCheck[base] {
			worstByCheck[base] = v
		}
	}
	for _, res := range results {
		if res.Err != nil && worstByCheck[res.Name] < 1 {
			worstByCheck[res.Name] = 1
		}
	}

	var b strings.Builder
	b.WriteString("# HELP dsd_up 1 if the dsd health scan completed.\n")
	b.WriteString("# TYPE dsd_up gauge\n")
	b.WriteString("dsd_up 1\n")

	b.WriteString("# HELP dsd_check_status Per-subsystem health (0=OK, 1=WARN, 2=CRIT).\n")
	b.WriteString("# TYPE dsd_check_status gauge\n")
	for _, res := range sortedResults(results) {
		// internal-runner-01-01: IsAvailable(nil) can't tell "genuinely not
		// applicable on this host" from "the collector failed/timed out"
		// (runner.RunAll synthesizes a nil-Data timeout Result on error) —
		// both leave Data nil. ApplyThresholds already converts every
		// r.Err != nil into an INFO insight unconditionally, so (matching the
		// same guard shouldHideRow/BuildSnapshot already use) only treat a
		// check as absent when there's ALSO no insight for it — a failed
		// collector must keep its series present (this file's own invariant:
		// "a check flipping OK→WARN is a value change, not a series
		// appearing/disappearing" applies just as much to running→failed).
		if !runner.IsAvailable(res.Data) && insightForResult(res.Name, insights) == nil {
			continue // absent collector — not "OK", just not present here
		}
		fmt.Fprintf(&b, "dsd_check_status{check=%q} %d\n", promLabel(res.Name), worstByCheck[res.Name])
	}

	// Coverage (DD-COVERAGE-1): a check that was not looked at has no finding, so
	// dsd_check_status reads 0 for it. These say whether the 0 means "looked".
	cov := Coverage(results, insights)
	b.WriteString("# HELP dsd_check_checked 1 if the check ran, 0 if it was not checked (errored, timed out, or its input unreadable). A check with a not-checked part still reads 1.\n")
	b.WriteString("# TYPE dsd_check_checked gauge\n")
	for _, cc := range cov.Checks {
		if cc.Coverage == models.CoverageNotApplicable {
			continue
		}
		checked := 0
		if cc.Coverage == models.CoverageChecked {
			checked = 1
		}
		fmt.Fprintf(&b, "dsd_check_checked{check=%q} %d\n", promLabel(cc.Name), checked)
	}
	b.WriteString("# HELP dsd_checks_coverage Number of checks by coverage: checked, not_checked (things not looked at) or not_applicable (nothing to check on this host).\n")
	b.WriteString("# TYPE dsd_checks_coverage gauge\n")
	fmt.Fprintf(&b, "dsd_checks_coverage{coverage=\"checked\"} %d\n", cov.Checked)
	fmt.Fprintf(&b, "dsd_checks_coverage{coverage=\"not_checked\"} %d\n", cov.NotChecked)
	fmt.Fprintf(&b, "dsd_checks_coverage{coverage=\"not_applicable\"} %d\n", cov.NotApplicable)
	b.WriteString("# HELP dsd_checks_not_checked Number of things not looked at, by reason.\n")
	b.WriteString("# TYPE dsd_checks_not_checked gauge\n")
	for _, reason := range models.CoverageReasons[:5] {
		fmt.Fprintf(&b, "dsd_checks_not_checked{reason=%q} %d\n", reason, cov.Reasons[reason])
	}

	b.WriteString("# HELP dsd_health_status Worst severity across all checks (0=OK, 1=WARN, 2=CRIT).\n")
	b.WriteString("# TYPE dsd_health_status gauge\n")
	fmt.Fprintf(&b, "dsd_health_status %d\n", Verdict(results, insights).Severity())
	return b.String()
}

// promSeverity maps a verdict level to the 0/1/2 metric scale (INFO/OK → 0).
func promSeverity(level string) int {
	switch level {
	case "CRIT":
		return 2
	case "WARN":
		return 1
	default:
		return 0
	}
}

// promLabel sanitizes a check name into a stable lowercase label value
// (e.g. "CPU Load" → "cpu_load"), collapsing runs of non-alphanumerics to one _.
func promLabel(name string) string {
	var b strings.Builder
	lastUnderscore := false
	for _, r := range strings.ToLower(name) {
		switch {
		case (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9'):
			b.WriteRune(r)
			lastUnderscore = false
		case !lastUnderscore:
			b.WriteByte('_')
			lastUnderscore = true
		}
	}
	return strings.Trim(b.String(), "_")
}
