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

	// PeerVerified is true when the kernel-reported SO_PEERCRED identity of the
	// socket's listener was obtained (never true under replay of a bundle
	// captured before this check existed — a recording gap, not a claim the
	// peer was checked and passed). PeerTrusted is meaningful only when
	// PeerVerified is true: it reports whether that kernel-verified UID is
	// root or the postgres service account. The socket directory list
	// includes /tmp, which an unprivileged local attacker can pre-create a
	// same-named socket in; without this check the collector would run psql
	// against — and could be fed fabricated metrics by — an impostor
	// listener. When PeerVerified && !PeerTrusted, metric collection is
	// skipped entirely rather than trusting the connection.
	PeerVerified bool `json:"peer_verified"`
	PeerTrusted  bool `json:"peer_trusted"`

	// Metrics — filled only when a local query succeeds.
	MetricsRead    bool    `json:"metrics_read"`
	MaxConnections int     `json:"max_connections,omitempty"`
	ActiveConns    int     `json:"active_conns,omitempty"`
	IdleInTxn      int     `json:"idle_in_txn,omitempty"`
	InRecovery     bool    `json:"in_recovery,omitempty"` // a standby/replica
	ReplayLagSec   float64 `json:"replay_lag_sec,omitempty"`
	// ReplayCaughtUp is true when the replica has replayed everything it has
	// received (pg_last_wal_receive_lsn() == pg_last_wal_replay_lsn()).
	// ReplayLagSec alone climbs unboundedly whenever the PRIMARY is simply
	// idle — no new transactions means pg_last_xact_replay_timestamp() never
	// advances — which is indistinguishable from a genuinely falling-behind
	// replica without this LSN check.
	ReplayCaughtUp bool `json:"replay_caught_up,omitempty"`

	StatusReason string `json:"status_reason,omitempty"`
}
