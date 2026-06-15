package models

// GrafanaInfo holds guest-side health for a local Grafana server. Gated on the HTTP
// API (3000) answering as Grafana. The headline signal is the backend DATABASE
// status from /api/health: Grafana stores dashboards, users, API keys, and alert
// rules in that database, so if it is not "ok" the whole instance is effectively
// down (dashboards won't load, alerting won't evaluate) even though the web port
// still answers. /api/health is unauthenticated. When it can't be read, HealthRead
// stays false — never a false green.
type GrafanaInfo struct {
	Detected bool   `json:"detected"`
	Version  string `json:"version,omitempty"`

	HealthRead     bool   `json:"health_read"`
	DatabaseOK     bool   `json:"database_ok,omitempty"`
	DatabaseStatus string `json:"database_status,omitempty"`

	StatusReason string `json:"status_reason,omitempty"`
}
