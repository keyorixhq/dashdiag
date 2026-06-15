package models

// PrometheusInfo holds guest-side health for a local Prometheus server. Gated on
// the HTTP API (9090) answering as Prometheus. Two headline signals: scrape
// targets that are DOWN (their series are silently not being collected — blind
// spots in monitoring) and a FAILED config reload (Prometheus keeps serving its
// last-good config, so recent edits are silently not applied). Reading the API
// needs no auth by default; when it can't be read, MetricsRead stays false — never
// a false green.
type PrometheusInfo struct {
	Detected bool   `json:"detected"`
	Version  string `json:"version,omitempty"`

	MetricsRead  bool   `json:"metrics_read"`
	TargetsTotal int    `json:"targets_total,omitempty"`
	TargetsDown  int    `json:"targets_down,omitempty"`
	DownSample   string `json:"down_sample,omitempty"`

	ConfigReloadRead bool `json:"config_reload_read,omitempty"`
	ConfigReloadOK   bool `json:"config_reload_ok,omitempty"`

	StatusReason string `json:"status_reason,omitempty"`
}
