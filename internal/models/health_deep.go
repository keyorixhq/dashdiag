package models

// CoreStat holds usage data for a single CPU core.
type CoreStat struct {
	Core     int     `json:"core"`
	UsagePct float64 `json:"usage_pct"`
}

// ProcessMemStat holds memory usage for a single process.
type ProcessMemStat struct {
	PID         int     `json:"pid"`
	Name        string  `json:"name"`
	RSSMB       float64 `json:"rss_mb"`
	MemPct      float64 `json:"mem_pct"`
	CgroupScope string  `json:"cgroup_scope,omitempty"` // "system:k3s.service", "container:abc", "kernel", etc.
}

// CgroupSlice is a top-level cgroup v2 slice with aggregated resource usage.
type CgroupSlice struct {
	Name         string  `json:"name"`           // "system.slice", "user.slice" etc.
	CPUUsagePct  float64 `json:"cpu_usage_pct"`  // throttled fraction (0–100)
	ThrottledPct float64 `json:"throttled_pct"`  // cpu.stat throttled_usec / total
	MemCurrentMB float64 `json:"mem_current_mb"` // memory.current bytes → MB
	MemLimitMB   float64 `json:"mem_limit_mb"`   // memory.max (−1 = unlimited)
	MemUsedPct   float64 `json:"mem_used_pct"`   // 0 when unlimited
	IOReadMBs    float64 `json:"io_read_mbs"`    // cumulative read MB (io.stat)
	IOWriteMBs   float64 `json:"io_write_mbs"`   // cumulative write MB
	HasCPULimit  bool    `json:"has_cpu_limit"`  // cpu.max ≠ "max 100000"
	HasMemLimit  bool    `json:"has_mem_limit"`  // memory.max ≠ "max"
}

// CgroupV2Info is the cgroup v2 summary added to HealthDeepInfo.
type CgroupV2Info struct {
	Available       bool          `json:"available"`
	Controllers     []string      `json:"controllers,omitempty"`
	Slices          []CgroupSlice `json:"slices,omitempty"`
	ThrottledSlices []string      `json:"throttled_slices,omitempty"` // slices with >5% throttle
	OOMKills        int           `json:"oom_kills"`                  // recent OOM kills from memory.events
}

// HealthDeepInfo holds extended system health data collected by HealthDeepCollector.
type HealthDeepInfo struct {
	// Per-core CPU usage (populated from /proc/stat delta)
	Cores         []CoreStat `json:"cores,omitempty"`
	MaxCorePct    float64    `json:"max_core_pct"`   // hottest core
	MinCorePct    float64    `json:"min_core_pct"`   // coolest core
	CoreImbalance float64    `json:"core_imbalance"` // max - min (high = single-threaded bottleneck)

	// 1-minute load average + core count, used to corroborate the instantaneous
	// per-core readings. Per-core %s are sampled while dsd's own deep collection
	// runs, which can peg every core on a small host; the load average predates
	// the run and is immune, so an "all cores saturated" verdict requires it.
	LoadAvg1 float64 `json:"load_avg_1"`
	NumCPU   int     `json:"num_cpu"`

	// Top memory consumers
	TopProcs     []ProcessMemStat `json:"top_procs,omitempty"` // top 10 by RSS
	TotalProcsMB float64          `json:"total_procs_mb"`      // sum of all process RSS

	// Extended memory breakdown from /proc/meminfo
	CachedMB    float64 `json:"cached_mb"`
	BuffersMB   float64 `json:"buffers_mb"`
	DirtyMB     float64 `json:"dirty_mb"`
	AnonPagesMB float64 `json:"anon_pages_mb"`

	// cgroup v2 slice summary
	Cgroup *CgroupV2Info `json:"cgroup,omitempty"`

	Status       string `json:"status,omitempty"`
	StatusReason string `json:"status_reason,omitempty"`
}
