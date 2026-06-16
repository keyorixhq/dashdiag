//go:build linux

package collectors

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"time"

	"github.com/keyorixhq/dashdiag/internal/models"
)

// esHTTPGet fetches url with a short timeout, tolerating self-signed TLS (local
// Elasticsearch defaults to a self-signed cert). Returns body, status code, err.
// Routed through the source cache (httpGetCached) so the response replays from the
// bundle instead of re-fetching the replaying machine.
func esHTTPGet(ctx context.Context, url string) ([]byte, int, error) {
	return httpGetCached(ctx, url)
}

// detectElasticsearch finds a local ES/OpenSearch node on 9200 and returns its
// base URL + identity. It checks http then https (8.x defaults to TLS). A 401
// still confirms the node (auth is on) — base URL is returned so the collector
// can report "detected but health needs credentials".
func detectElasticsearch(ctx context.Context) (info *models.ElasticsearchInfo) {
	// Cheap pre-check: is anything on 9200 at all?
	if !dialReachable("tcp", "127.0.0.1:9200", 300*time.Millisecond) {
		return nil
	}

	for _, base := range []string{"http://127.0.0.1:9200", "https://127.0.0.1:9200"} {
		body, code, err := esHTTPGet(ctx, base+"/")
		if err != nil {
			continue
		}
		// 401 = ES with security on (auth required) — confirmed, no body identity.
		if code == http.StatusUnauthorized {
			return &models.ElasticsearchInfo{Detected: true, BaseURL: base, Distribution: "elasticsearch"}
		}
		var root struct {
			ClusterName string `json:"cluster_name"`
			Tagline     string `json:"tagline"`
			Version     struct {
				Number       string `json:"number"`
				Distribution string `json:"distribution"`
			} `json:"version"`
		}
		if json.Unmarshal(body, &root) == nil && (root.ClusterName != "" || strings.Contains(root.Tagline, "Search")) {
			dist := root.Version.Distribution
			if dist == "" {
				dist = "elasticsearch"
			}
			return &models.ElasticsearchInfo{
				Detected: true, BaseURL: base, ClusterName: root.ClusterName,
				Version: root.Version.Number, Distribution: dist,
			}
		}
	}
	return nil
}

// ElasticsearchAvailable reports whether a local ES/OpenSearch node is answering.
func ElasticsearchAvailable() bool { return detectElasticsearch(context.Background()) != nil }

type ElasticsearchCollector struct{}

func NewElasticsearchCollector() *ElasticsearchCollector { return &ElasticsearchCollector{} }

func (c *ElasticsearchCollector) Name() string           { return "Elasticsearch" }
func (c *ElasticsearchCollector) Timeout() time.Duration { return 6 * time.Second }

func (c *ElasticsearchCollector) Collect(ctx context.Context) (interface{}, error) {
	info := detectElasticsearch(ctx)
	if info == nil {
		return &models.ElasticsearchInfo{Detected: false}, nil
	}

	body, code, err := esHTTPGet(ctx, info.BaseURL+"/_cluster/health")
	if err != nil || code != http.StatusOK {
		info.StatusReason = "cluster health unavailable (authentication required — pass credentials)"
		return info, nil
	}
	var h struct {
		ClusterName      string  `json:"cluster_name"`
		Status           string  `json:"status"`
		NumberOfNodes    int     `json:"number_of_nodes"`
		UnassignedShards int     `json:"unassigned_shards"`
		ActiveShardsPct  float64 `json:"active_shards_percent_as_number"`
	}
	if json.Unmarshal(body, &h) != nil || h.Status == "" {
		info.StatusReason = "cluster health response could not be parsed"
		return info, nil
	}
	info.HealthRead = true
	info.Status = h.Status
	info.Nodes = h.NumberOfNodes
	info.UnassignedShards = h.UnassignedShards
	info.ActiveShardsPct = h.ActiveShardsPct
	if info.ClusterName == "" {
		info.ClusterName = h.ClusterName
	}
	return info, nil
}
