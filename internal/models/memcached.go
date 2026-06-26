package models

// MemcachedInfo holds guest-side health for a local memcached server. Gated on a
// server that answers the memcached text protocol on port 11211. Unlike a blocking
// store, memcached degrades by evicting — so its signals are WARN-level cache
// pressure (memory at its limit, connections near maxconns), not hard outages.
type MemcachedInfo struct {
	Detected bool   `json:"detected"`
	Addr     string `json:"addr,omitempty"`
	Version  string `json:"version,omitempty"`

	MetricsRead     bool `json:"metrics_read"`
	CurrConnections int  `json:"curr_connections,omitempty"`
	MaxConnections  int  `json:"max_connections,omitempty"`
	// MaxConnsRead is true only when a real max_connections/maxconns value was
	// parsed (from plain stats or the `stats settings` fallback). Without it a
	// build that exposes neither left MaxConnections=0 and the connection-saturation
	// check silently couldn't run — a green verdict with one metric unassessed.
	MaxConnsRead  bool  `json:"max_conns_read,omitempty"`
	UsedBytes     int64 `json:"used_bytes,omitempty"`
	LimitMaxBytes int64 `json:"limit_max_bytes,omitempty"`
	Evictions     int64 `json:"evictions,omitempty"`    // cumulative since start
	EvictingNow   bool  `json:"evicting_now,omitempty"` // evictions rose during a short sample
	CurrItems     int64 `json:"curr_items,omitempty"`

	StatusReason string `json:"status_reason,omitempty"`
}
