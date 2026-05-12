package models

// CoreStat holds usage data for a single CPU core.
type CoreStat struct {
	Core     int     `json:"core"`
	UsagePct float64 `json:"usage_pct"`
}

// ProcessMemStat holds memory usage for a single process.
type ProcessMemStat struct {
	PID    int     `json:"pid"`
	Name   string  `json:"name"`
	RSSMB  float64 `json:"rss_mb"`
	MemPct float64 `json:"mem_pct"`
}

// HealthDeepInfo holds extended system health data collected by HealthDeepCollector.
type HealthDeepInfo struct {
	// Per-core CPU usage (populated from /proc/stat delta)
	Cores         []CoreStat `json:"cores,omitempty"`
	MaxCorePct    float64    `json:"max_core_pct"`   // hottest core
	MinCorePct    float64    `json:"min_core_pct"`   // coolest core
	CoreImbalance float64    `json:"core_imbalance"` // max - min (high = single-threaded bottleneck)

	// Top memory consumers
	TopProcs     []ProcessMemStat `json:"top_procs,omitempty"` // top 10 by RSS
	TotalProcsMB float64          `json:"total_procs_mb"`      // sum of all process RSS

	// Extended memory breakdown from /proc/meminfo
	CachedMB    float64 `json:"cached_mb"`
	BuffersMB   float64 `json:"buffers_mb"`
	DirtyMB     float64 `json:"dirty_mb"`
	AnonPagesMB float64 `json:"anon_pages_mb"`

	Status       string `json:"status,omitempty"`
	StatusReason string `json:"status_reason,omitempty"`
}
