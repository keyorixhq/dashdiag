package analysis

import (
	"fmt"

	"github.com/keyorixhq/dashdiag/internal/models"
)

// checkTraefik surfaces health for a local Traefik proxy. Gated on Detected. The
// headline signal is routers in ERROR: Traefik disables a router whose rule,
// service, or middleware doesn't resolve, so that route silently stops being served
// (404/502 for that host/path) while the rest of the proxy keeps working. Never a
// silent OK when the API couldn't be read.
func checkTraefik(t models.TraefikInfo) []models.Insight {
	if !t.Detected {
		return nil
	}

	if !t.APIRead {
		return []models.Insight{unverifiedInsight("INFO", "Traefik",
			"Traefik is up, but its API could not be read",
			[]string{
				"note: enable the API (api.insecure on :8080, or a secured api endpoint) to surface router health",
				"to inspect: curl -s localhost:8080/api/overview",
			},
		)}
	}

	var out []models.Insight

	// Routers in error are disabled — their routes return 404/502.
	if t.RoutersErrors > 0 {
		out = append(out, insight("WARN", "Traefik",
			fmt.Sprintf("%d of %d HTTP router(s) are in ERROR — Traefik has disabled them, so those routes are not served (404/502)", t.RoutersErrors, t.RoutersTotal),
			[]string{
				"to inspect: curl -s localhost:8080/api/http/routers | jq '.[]|select(.status!=\"enabled\")'",
				"note: a router errors when its rule is invalid or it references a missing service/middleware — check the dynamic config",
			}))
	}

	// Service/middleware errors break the targets routers point at.
	if t.ServicesErrors > 0 || t.MiddlewareErrors > 0 {
		out = append(out, insight("WARN", "Traefik",
			fmt.Sprintf("Traefik dynamic config has %d service error(s) and %d middleware error(s) — routes depending on them will fail", t.ServicesErrors, t.MiddlewareErrors),
			[]string{
				"to inspect: curl -s localhost:8080/api/http/services | jq '.[]|select(.status!=\"enabled\")'",
				"note: check that referenced backends and middlewares exist and are valid in the dynamic config",
			}))
	}

	return out
}
