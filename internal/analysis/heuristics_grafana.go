package analysis

import (
	"fmt"

	"github.com/keyorixhq/dashdiag/internal/models"
)

// checkGrafana surfaces health for a local Grafana server. Gated on Detected. The
// headline signal is the backend DATABASE status: Grafana keeps dashboards, users,
// API keys, and alert rules in that database, so if it is not "ok" the instance is
// effectively down (dashboards won't load, alerting won't evaluate) even while the
// web port still answers. Never a silent OK when health couldn't be read.
func checkGrafana(g models.GrafanaInfo) []models.Insight {
	if !g.Detected {
		return nil
	}

	if !g.HealthRead {
		return []models.Insight{insight("INFO", "Grafana",
			"Grafana is up, but its health endpoint could not be read",
			[]string{
				"note: /api/health should be reachable without auth (a reverse proxy may block it)",
				"to inspect: curl -s localhost:3000/api/health",
			},
		)}
	}

	if !g.DatabaseOK {
		status := g.DatabaseStatus
		if status == "" {
			status = "unknown"
		}
		return []models.Insight{insight("CRIT", "Grafana",
			fmt.Sprintf("backend database is not OK (status: %q) — dashboards, users, and alerting are unavailable while the web port still answers", status),
			[]string{
				"to inspect: curl -s localhost:3000/api/health",
				"note: check the configured database (sqlite file permissions, or the external MySQL/Postgres host) and the Grafana log",
			})}
	}

	return nil
}
