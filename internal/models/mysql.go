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
	// ConnStatsRead is true only when BOTH the max_connections and Threads_connected
	// queries returned. VERSION() succeeding (→ MetricsRead) does NOT cover them;
	// without this flag a failed either-query left a count at 0 and the
	// connection-saturation check silently couldn't run.
	ConnStatsRead bool `json:"conn_stats_read,omitempty"`
	IsReplica     bool `json:"is_replica,omitempty"`
	SecondsBehind int  `json:"seconds_behind,omitempty"` // replica lag (Seconds_Behind_Master)
	// ReplStopped is true when this is a replica whose replication is NOT running
	// (Slave_IO_Running or Slave_SQL_Running is not "Yes"). In that state
	// Seconds_Behind_Master reads NULL, so the lag check alone reports 0s and the
	// replica looks healthy while silently serving ever-staler data — a false-OK.
	ReplStopped bool `json:"repl_stopped,omitempty"`

	StatusReason string `json:"status_reason,omitempty"`
}
