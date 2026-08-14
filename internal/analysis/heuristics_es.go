package analysis

import (
	"fmt"

	"github.com/keyorixhq/dashdiag/internal/models"
)

const (
	esCatElastic        = "Elasticsearch"
	esInspectCurlSK     = "to inspect: curl -sk "
	esClusterHealthPath = "/_cluster/health?pretty"
)

// checkElasticsearch surfaces cluster-health issues for a local Elasticsearch or
// OpenSearch node. Gated on Detected. The cluster status is the headline:
// red = primary shards unassigned (data unavailable), yellow = replicas
// unassigned (no redundancy). Never a silent OK when health couldn't be read.
func checkElasticsearch(e models.ElasticsearchInfo) []models.Insight {
	if !e.Detected {
		return nil
	}
	name := esCatElastic
	if e.Distribution == "opensearch" {
		name = "OpenSearch"
	}

	var out []models.Insight
	if e.IdentityUnverified {
		// internal-collectors-11-04: detection trusted any process bound to the
		// ES port that returned an ES-shaped HTTP response — an unprivileged
		// local process could otherwise spoof a fake "green" cluster to mask a
		// real outage. Disclose alongside (never replacing) whatever status
		// insight follows, so the operator can judge the confidence themselves.
		out = append(out, unverifiedInsight("INFO", esCatElastic,
			name+" was detected via an HTTP response shape match only — the listening process's identity could not be confirmed",
			[]string{"note: run as root, or verify with: ss -tlnp | grep :9200"}))
	}

	if !e.HealthRead {
		return append(out, unverifiedInsight("INFO", esCatElastic,
			name+" is reachable, but cluster health could not be read",
			[]string{
				"note: modern Elasticsearch defaults to TLS + auth — pass credentials for the cluster-health check",
				"to inspect: curl -sk -u <user>:<pass> " + e.BaseURL + esClusterHealthPath,
			},
		))
	}

	switch e.Status {
	case "red":
		msg := fmt.Sprintf("%s cluster is RED — primary shards are unassigned, so some data is UNAVAILABLE", name)
		if e.UnassignedShards > 0 {
			msg += fmt.Sprintf(" (%d unassigned shard(s), %.0f%% active)", e.UnassignedShards, e.ActiveShardsPct)
		}
		return append(out, insight("CRIT", esCatElastic, msg,
			[]string{
				esInspectCurlSK + e.BaseURL + "/_cluster/allocation/explain?pretty",
				esInspectCurlSK + e.BaseURL + "/_cat/shards?v | grep -v STARTED",
				"note: common causes — a node left the cluster, disk watermark exceeded, or a corrupt shard",
			}))
	case "yellow":
		msg := fmt.Sprintf("%s cluster is YELLOW — replica shards are unassigned, so there is no redundancy", name)
		if e.UnassignedShards > 0 {
			msg += fmt.Sprintf(" (%d unassigned replica(s))", e.UnassignedShards)
		}
		return append(out, insight("WARN", esCatElastic, msg,
			[]string{
				esInspectCurlSK + e.BaseURL + esClusterHealthPath,
				"note: common on a single-node cluster (replicas can't be placed) — set index replicas to 0, or add a node",
			}))
	case "green":
		// Status genuinely green (or spoofed — see the IdentityUnverified
		// disclosure above, already in `out` if applicable). Must still
		// return `out` here, not a hardcoded nil: a spoofed-green response is
		// exactly the attack this finding describes, and nil would silently
		// drop the disclosure that's the whole point of the fix.
		return out
	default:
		// internal-analysis-04-01: an unrecognized status string must not fall
		// through as if it were "green" — HealthRead only confirms the JSON
		// parsed and status was non-empty, not that status is one of the three
		// real ES/OpenSearch enum values. A non-ES service answering this port
		// (or a tampered response) could otherwise report as fully healthy.
		return append(out, unverifiedInsight("INFO", esCatElastic,
			fmt.Sprintf("%s cluster status %q is not a recognized state (expected green/yellow/red) — health could not be confirmed", name, e.Status),
			[]string{
				"note: an unrecognized status can mean a non-Elasticsearch service is answering this port, or an incompatible/tampered response",
				esInspectCurlSK + e.BaseURL + esClusterHealthPath,
			}))
	}
}
