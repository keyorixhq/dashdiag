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

	if !e.StatsRead {
		return []models.Insight{unverifiedInsight("INFO", "Envoy",
			"Envoy's admin interface is up, but its cluster stats could not be read",
			[]string{
				"note: the admin interface must be reachable to read upstream health",
				"to inspect: curl -s localhost:9901/clusters",
			},
		)}
	}

	// Stats endpoint answered (StatsRead) but no upstream cluster with members was
	// parsed out of it — a garbled/empty response, a filter that matched nothing, or
	// an Envoy whose membership stats use unexpected names. Upstream health was never
	// actually assessed, so surface it rather than let all-zeros pass as clean.
	if e.ClustersTotal == 0 {
		return []models.Insight{unverifiedInsight("INFO", "Envoy",
			"Envoy admin stats were read, but no upstream cluster membership data was found — upstream host health could not be verified",
			[]string{
				"to inspect: curl -s localhost:9901/stats | grep membership_",
				"note: an Envoy with no configured upstream clusters will also show this",
			},
		)}
	}

	// A cluster with zero healthy hosts can serve nothing behind it.
	if e.FullyDownClusters > 0 {
		msg := fmt.Sprintf("%d upstream cluster(s) have ZERO healthy hosts — all requests to those backends fail (503)", e.FullyDownClusters)
		if e.DegradedSample != "" {
			msg += " (e.g. " + e.DegradedSample + ")"
		}
		return []models.Insight{insight("CRIT", "Envoy", msg, envoyClusterSteps())}
	}

	// Some upstream hosts unhealthy — partial capacity loss / retries.
	if e.UpstreamsTotal > 0 && e.UpstreamsHealthy < e.UpstreamsTotal {
		down := e.UpstreamsTotal - e.UpstreamsHealthy
		msg := fmt.Sprintf("%d of %d upstream host(s) are unhealthy — requests load-balanced to them fail (503)", down, e.UpstreamsTotal)
		if e.DegradedSample != "" {
			msg += " (e.g. " + e.DegradedSample + ")"
		}
		return []models.Insight{insight("WARN", "Envoy", msg, envoyClusterSteps())}
	}

	return nil
}

func envoyClusterSteps() []string {
	return []string{
		"to inspect: curl -s localhost:9901/clusters | grep health_flags",
		"note: a host goes unhealthy when its active health check fails — check the backend is up and the health-check path/port are correct",
	}
}
