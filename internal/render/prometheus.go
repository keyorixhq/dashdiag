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
// Severity is the same 0/1/2 scale as dsd's exit code (INFO counts as OK). A
// per-check series is emitted for every subsystem that actually ran, so a check
// flipping OK→WARN is a value change, not a series appearing/disappearing.
func PrometheusMetrics(results []runner.Result, insights []models.Insight) string {
	worstByCheck := map[string]int{}
	overall := 0
	for _, ins := range insights {
		v := promSeverity(ins.Level)
		if v > worstByCheck[ins.Check] {
			worstByCheck[ins.Check] = v
		}
		if v > overall {
			overall = v
		}
	}

	var b strings.Builder
	b.WriteString("# HELP dsd_up 1 if the dsd health scan completed.\n")
	b.WriteString("# TYPE dsd_up gauge\n")
	b.WriteString("dsd_up 1\n")

	b.WriteString("# HELP dsd_check_status Per-subsystem health (0=OK, 1=WARN, 2=CRIT).\n")
	b.WriteString("# TYPE dsd_check_status gauge\n")
	for _, res := range sortedResults(results) {
		if !runner.IsAvailable(res.Data) {
			continue // absent collector — not "OK", just not present here
		}
		b.WriteString(fmt.Sprintf("dsd_check_status{check=%q} %d\n", promLabel(res.Name), worstByCheck[res.Name]))
	}

	b.WriteString("# HELP dsd_health_status Worst severity across all checks (0=OK, 1=WARN, 2=CRIT).\n")
	b.WriteString("# TYPE dsd_health_status gauge\n")
	b.WriteString(fmt.Sprintf("dsd_health_status %d\n", overall))
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
