package analysis

import (
	"fmt"

	"github.com/keyorixhq/dashdiag/internal/models"
)

// checkEnvoy surfaces health for a local Envoy proxy. Gated on Detected. The
// headline signal is upstream host health: when a cluster's hosts fail health
// checks, requests routed to them return 503. A cluster with ZERO healthy hosts is a
// hard outage for everything behind it (CRIT); partially-unhealthy upstreams are a
// WARN. Never a silent OK when the admin stats couldn't be read.
func checkEnvoy(e models.EnvoyInfo) []models.Insight {
	if !e.Detected {
		return nil
	}

	var out []models.Insight
	if e.IdentityUnverified {
		// internal-collectors-12-01 / internal-analysis-03-03: the
		// {version,state} shape check can be spoofed by any unprivileged
		// local process binding :9901 first, and the stats fields below are
		// trusted with no cross-check that the responder is really Envoy —
		// a spoofed "everything healthy" response would otherwise return nil
		// here, the same silent-clean result a genuinely healthy Envoy gets.
		// Disclose alongside (never replacing) whatever finding follows.
		out = append(out, unverifiedInsight("INFO", "Envoy",
			"Envoy was detected via an HTTP response shape match only — the listening process's identity could not be confirmed",
			[]string{"note: run as root, or verify with: ss -tlnp | grep :9901"}))
	}

	if !e.StatsRead {
		return append(out, unverifiedInsight("INFO", "Envoy",
			"Envoy's admin interface is up, but its cluster stats could not be read",
			[]string{
				"note: the admin interface must be reachable to read upstream health",
				"to inspect: curl -s localhost:9901/clusters",
			},
		))
	}

	// Stats endpoint answered (StatsRead) but no upstream cluster with members was
	// parsed out of it — a garbled/empty response, a filter that matched nothing, or
	// an Envoy whose membership stats use unexpected names. Upstream health was never
	// actually assessed, so surface it rather than let all-zeros pass as clean.
	if e.ClustersTotal == 0 {
		return append(out, unverifiedInsight("INFO", "Envoy",
			"Envoy admin stats were read, but no upstream cluster membership data was found — upstream host health could not be verified",
			[]string{
				"to inspect: curl -s localhost:9901/stats | grep membership_",
				"note: an Envoy with no configured upstream clusters will also show this",
			},
		))
	}

	// internal-analysis-03-03: UpstreamsHealthy > UpstreamsTotal is impossible
	// from a real Envoy — either a malformed/inconsistent response (parse
	// mismatch) or a spoofed one. Trusting it would compute a nonsensical
	// negative "down" count below and silently fall through as healthy.
	if e.UpstreamsHealthy > e.UpstreamsTotal {
		return append(out, unverifiedInsight("INFO", "Envoy",
			fmt.Sprintf("Envoy admin stats report %d healthy of %d total upstream hosts — an impossible count, the response could not be trusted", e.UpstreamsHealthy, e.UpstreamsTotal),
			[]string{"to inspect: curl -s localhost:9901/stats | grep membership_"},
		))
	}

	// A cluster with zero healthy hosts can serve nothing behind it.
	if e.FullyDownClusters > 0 {
		msg := fmt.Sprintf("%d upstream cluster(s) have ZERO healthy hosts — all requests to those backends fail (503)", e.FullyDownClusters)
		if e.DegradedSample != "" {
			msg += " (e.g. " + e.DegradedSample + ")"
		}
		return append(out, insight("CRIT", "Envoy", msg, envoyClusterSteps()))
	}

	// Some upstream hosts unhealthy — partial capacity loss / retries.
	if e.UpstreamsTotal > 0 && e.UpstreamsHealthy < e.UpstreamsTotal {
		down := e.UpstreamsTotal - e.UpstreamsHealthy
		msg := fmt.Sprintf("%d of %d upstream host(s) are unhealthy — requests load-balanced to them fail (503)", down, e.UpstreamsTotal)
		if e.DegradedSample != "" {
			msg += " (e.g. " + e.DegradedSample + ")"
		}
		return append(out, insight("WARN", "Envoy", msg, envoyClusterSteps()))
	}

	return out
}

func envoyClusterSteps() []string {
	return []string{
		"to inspect: curl -s localhost:9901/clusters | grep health_flags",
		"note: a host goes unhealthy when its active health check fails — check the backend is up and the health-check path/port are correct",
	}
}
