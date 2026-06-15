package models

// PostgresInfo holds guest-side health for a locally-running PostgreSQL server.
// It is gated on a reachable local Postgres socket (silent otherwise), and
// degrades gracefully: the liveness fields (Accepting) need no auth, while the
// metric fields are filled only when a local query succeeds (peer auth as the
// postgres OS user / root). MetricsRead distinguishes "healthy" from "couldn't
// look" so an inaccessible server is never reported as OK.
type PostgresInfo struct {
	Detected      bool   `json:"detected"`
	SocketDir     string `json:"socket_dir,omitempty"`
	ServerVersion string `json:"server_version,omitempty"`

	// Liveness — from pg_isready (no auth needed).
	Accepting    bool   `json:"accepting"`
	AcceptReason string `json:"accept_reason,omitempty"` // pg_isready text when not accepting

	// Metrics — filled only when a local query succeeds.
	MetricsRead    bool    `json:"metrics_read"`
	MaxConnections int     `json:"max_connections,omitempty"`
	ActiveConns    int     `json:"active_conns,omitempty"`
	IdleInTxn      int     `json:"idle_in_txn,omitempty"`
	InRecovery     bool    `json:"in_recovery,omitempty"` // a standby/replica
	ReplayLagSec   float64 `json:"replay_lag_sec,omitempty"`

	StatusReason string `json:"status_reason,omitempty"`
}
