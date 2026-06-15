package models

// MySQLInfo holds guest-side health for a locally-running MySQL or MariaDB
// server. Gated on a reachable local socket (silent otherwise) and degrades
// gracefully: liveness needs no auth, while the metric fields are filled only
// when a local query succeeds (socket auth as root). MetricsRead distinguishes
// "healthy" from "couldn't look" so an inaccessible server is never reported OK.
type MySQLInfo struct {
	Detected   bool   `json:"detected"`
	SocketPath string `json:"socket_path,omitempty"`
	Flavor     string `json:"flavor,omitempty"`  // "MariaDB" or "MySQL"
	Version    string `json:"version,omitempty"` // server version string

	Accepting bool `json:"accepting"` // socket reachable / server responding

	MetricsRead      bool `json:"metrics_read"`
	MaxConnections   int  `json:"max_connections,omitempty"`
	ThreadsConnected int  `json:"threads_connected,omitempty"`
	IsReplica        bool `json:"is_replica,omitempty"`
	SecondsBehind    int  `json:"seconds_behind,omitempty"` // replica lag (Seconds_Behind_Master)

	StatusReason string `json:"status_reason,omitempty"`
}
