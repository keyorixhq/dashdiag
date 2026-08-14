package models

// AlertmanagerInfo holds guest-side health for a local Prometheus Alertmanager.
// Gated on the HTTP API (9093) answering as Alertmanager. The headline signal is a
// FAILED config reload (Alertmanager keeps serving its last-good routing/receiver
// config, so recent edits are silently not applied). ClusterStatus/ClusterPeers are
// collected for context only — "settling" is a normal startup transient that
// resolves to "ready" within seconds, so the heuristic does not alert on it. When
// the API can't be read, StatusRead stays false — never a false green.
type AlertmanagerInfo struct {
	Detected bool   `json:"detected"`
	Version  string `json:"version,omitempty"`

	StatusRead    bool   `json:"status_read"`
	ClusterStatus string `json:"cluster_status,omitempty"`
	ClusterPeers  int    `json:"cluster_peers,omitempty"`

	ConfigReloadRead bool `json:"config_reload_read,omitempty"`
	ConfigReloadOK   bool `json:"config_reload_ok,omitempty"`

	StatusReason string `json:"status_reason,omitempty"`
	// IdentityUnverified is true when the process listening on the Alertmanager
	// port could not be confirmed via its own cmdline — only an unauthenticated
	// HTTP response shape matched. Any unprivileged local process can otherwise
	// spoof a fake "healthy" verdict by binding the port first.
	IdentityUnverified bool `json:"identity_unverified,omitempty"`
}
