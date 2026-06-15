package models

// ElasticsearchInfo holds guest-side health for a local Elasticsearch or
// OpenSearch node. Gated on the HTTP API (9200) answering. The headline is the
// cluster status: red means primary shards are unassigned (data is unavailable);
// yellow means replicas are unassigned (no redundancy). Modern Elasticsearch
// defaults to TLS + auth, so cluster health needs credentials — when it can't be
// read, HealthRead stays false (never a false green).
type ElasticsearchInfo struct {
	Detected     bool   `json:"detected"`
	Distribution string `json:"distribution,omitempty"` // elasticsearch | opensearch
	Version      string `json:"version,omitempty"`
	ClusterName  string `json:"cluster_name,omitempty"`
	BaseURL      string `json:"base_url,omitempty"`

	HealthRead       bool    `json:"health_read"`
	Status           string  `json:"status,omitempty"` // green | yellow | red
	Nodes            int     `json:"nodes,omitempty"`
	UnassignedShards int     `json:"unassigned_shards,omitempty"`
	ActiveShardsPct  float64 `json:"active_shards_pct,omitempty"`

	StatusReason string `json:"status_reason,omitempty"`
}
