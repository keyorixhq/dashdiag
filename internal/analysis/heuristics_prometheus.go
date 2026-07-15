package analysis

import (
	"fmt"

	"github.com/keyorixhq/dashdiag/internal/models"
)

const catPrometheus = "Prometheus"

// checkPrometheus surfaces health for a local Prometheus server. Gated on Detected.
// Two headline signals: scrape targets that are DOWN (their series are silently not
// collected — monitoring blind spots) and a FAILED config reload (Prometheus keeps
// serving its last-good config, so recent edits are not applied). Never a silent OK
// when the API couldn't be read.
func checkPrometheus(p models.PrometheusInfo) []models.Insight {
	if !p.Detected {
		return nil
	}

	if !p.MetricsRead {
		return []models.Insight{insight("INFO", catPrometheus,
			"Prometheus is up, but its API could not be read",
			[]string{
				"note: the targets API must be reachable (a reverse proxy or auth may block it)",
				"to inspect: curl -s localhost:9090/api/v1/targets",
			},
		)}
	}

	var out []models.Insight

	// A failed config reload means recent edits are silently not applied.
	if p.ConfigReloadRead && !p.ConfigReloadOK {
		out = append(out, insight("WARN", catPrometheus,
			"configuration reload FAILED — Prometheus is serving its last-good config, so recent rule/scrape edits are not applied",
			[]string{
				"to inspect: promtool check config /etc/prometheus/prometheus.yml",
				"note: check the Prometheus log for the parse error, then reload (SIGHUP or POST /-/reload)",
			}))
	}

	// Scrape targets that are down: their metrics are not being collected.
	switch {
	case p.TargetsTotal > 0 && p.TargetsDown == p.TargetsTotal:
		out = append(out, insight("CRIT", catPrometheus,
			fmt.Sprintf("ALL %d scrape target(s) are DOWN — Prometheus is collecting nothing (monitoring is blind)", p.TargetsTotal),
			promTargetSteps(p.DownSample)))
	case p.TargetsDown > 0:
		out = append(out, insight("WARN", catPrometheus,
			fmt.Sprintf("%d of %d scrape target(s) are DOWN — their series are not being collected (blind spots)", p.TargetsDown, p.TargetsTotal),
			promTargetSteps(p.DownSample)))
	}

	return out
}

func promTargetSteps(sample string) []string {
	steps := []string{
		"to inspect: curl -s 'localhost:9090/api/v1/targets?state=active' | jq '.data.activeTargets[]|select(.health==\"down\")'",
		"note: a target goes down when its endpoint is unreachable, times out, or returns non-200 — check the exporter and network path",
	}
	if sample != "" {
		steps = append([]string{"e.g. " + sample}, steps...)
	}
	return steps
}
