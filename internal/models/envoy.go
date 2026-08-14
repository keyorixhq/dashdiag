package models

// EnvoyInfo holds guest-side health for a local Envoy proxy. Gated on the admin
// interface (commonly :9901) answering as Envoy. The headline signal is upstream
// host health: Envoy load-balances to upstream clusters, and when a cluster's hosts
// fail health checks, requests routed to them return 503. A cluster with ZERO
// healthy hosts is a hard outage for everything behind it. Reading the admin stats
// needs the interface reachable; when it can't be read, StatsRead stays false —
// never a false green.
type EnvoyInfo struct {
	Detected bool   `json:"detected"`
	Version  string `json:"version,omitempty"`
	State    string `json:"state,omitempty"` // LIVE / DRAINING / PRE_INITIALIZING (context only)

	StatsRead         bool   `json:"stats_read"`
	ClustersTotal     int    `json:"clusters_total,omitempty"`
	UpstreamsTotal    int    `json:"upstreams_total,omitempty"`
	UpstreamsHealthy  int    `json:"upstreams_healthy,omitempty"`
	FullyDownClusters int    `json:"fully_down_clusters,omitempty"`
	DegradedSample    string `json:"degraded_sample,omitempty"`

	StatusReason string `json:"status_reason,omitempty"`
	// IdentityUnverified is true when the process listening on the Envoy admin
	// port could not be confirmed via its own cmdline — only an unauthenticated
	// HTTP response shape matched. Any unprivileged local process can otherwise
	// spoof a fake "healthy" verdict by binding the port first.
	IdentityUnverified bool `json:"identity_unverified,omitempty"`
}
