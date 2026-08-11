package analysis

import (
	"fmt"

	"github.com/keyorixhq/dashdiag/internal/models"
)

const (
	esCatElastic    = "Elasticsearch"
	esInspectCurlSK = "to inspect: curl -sk "
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

	if !e.HealthRead {
		return []models.Insight{unverifiedInsight("INFO", esCatElastic,
			name+" is reachable, but cluster health could not be read",
			[]string{
				"note: modern Elasticsearch defaults to TLS + auth — pass credentials for the cluster-health check",
				"to inspect: curl -sk -u <user>:<pass> " + e.BaseURL + "/_cluster/health?pretty",
			},
		)}
	}

	switch e.Status {
	case "red":
		msg := fmt.Sprintf("%s cluster is RED — primary shards are unassigned, so some data is UNAVAILABLE", name)
		if e.UnassignedShards > 0 {
			msg += fmt.Sprintf(" (%d unassigned shard(s), %.0f%% active)", e.UnassignedShards, e.ActiveShardsPct)
		}
		return []models.Insight{insight("CRIT", esCatElastic, msg,
			[]string{
				esInspectCurlSK + e.BaseURL + "/_cluster/allocation/explain?pretty",
				esInspectCurlSK + e.BaseURL + "/_cat/shards?v | grep -v STARTED",
				"note: common causes — a node left the cluster, disk watermark exceeded, or a corrupt shard",
			})}
	case "yellow":
		msg := fmt.Sprintf("%s cluster is YELLOW — replica shards are unassigned, so there is no redundancy", name)
		if e.UnassignedShards > 0 {
			msg += fmt.Sprintf(" (%d unassigned replica(s))", e.UnassignedShards)
		}
		return []models.Insight{insight("WARN", esCatElastic, msg,
			[]string{
				esInspectCurlSK + e.BaseURL + "/_cluster/health?pretty",
				"note: common on a single-node cluster (replicas can't be placed) — set index replicas to 0, or add a node",
			})}
	}
	return nil
}
