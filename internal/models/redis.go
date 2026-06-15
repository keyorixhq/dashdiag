package models

// RedisInfo holds guest-side health for a local Redis (or Valkey) server. Gated
// on a server that answers PING (silent otherwise) and degrades gracefully:
// liveness needs no client, while the metric fields are filled only when
// `redis-cli INFO` succeeds. MetricsRead distinguishes "healthy" from "couldn't
// look" so an inaccessible server is never reported OK.
type RedisInfo struct {
	Detected bool   `json:"detected"`
	Addr     string `json:"addr,omitempty"` // socket path or host:port that answered PING
	Version  string `json:"version,omitempty"`

	Accepting bool `json:"accepting"` // answered PING

	MetricsRead      bool `json:"metrics_read"`
	ConnectedClients int  `json:"connected_clients,omitempty"`
	MaxClients       int  `json:"max_clients,omitempty"`
	// MaxClientsRead is true only when the separate `CONFIG GET maxclients` query
	// returned. INFO succeeding (→ MetricsRead) does NOT cover it; without this flag
	// a failed maxclients read left MaxClients=0 and the client-saturation check
	// silently couldn't run.
	MaxClientsRead  bool   `json:"max_clients_read,omitempty"`
	UsedMemoryBytes int64  `json:"used_memory_bytes,omitempty"`
	MaxMemoryBytes  int64  `json:"max_memory_bytes,omitempty"` // 0 = no limit (no eviction)
	MaxMemoryPolicy string `json:"max_memory_policy,omitempty"`
	Role            string `json:"role,omitempty"` // master | slave
	ReplLinkDown    bool   `json:"repl_link_down,omitempty"`
	ReplLastIOSec   int    `json:"repl_last_io_sec,omitempty"`
	LastSaveOK      bool   `json:"last_save_ok"` // rdb_last_bgsave_status == ok
	LastSaveKnown   bool   `json:"-"`            // whether persistence status was reported

	StatusReason string `json:"status_reason,omitempty"`
}
