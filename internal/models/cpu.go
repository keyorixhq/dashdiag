package models

type CPUInfo struct {
	LoadAvg1     float64 `json:"load_avg_1"`
	LoadAvg5     float64 `json:"load_avg_5"`
	LoadAvg15    float64 `json:"load_avg_15"`
	NumCPU       int     `json:"num_cpu"`
	UsagePct     float64 `json:"usage_pct"`
	LoadPct      float64 `json:"load_pct"`
	// StealPct is the percentage of CPU time stolen by the hypervisor.
	// Non-zero only on virtual machines. > 10% indicates host over-provisioning.
	StealPct float64 `json:"steal_pct"`
	// IOwaitPct is the percentage of time the CPU was idle waiting for I/O.
	// High iowait (> 20%) with high load_pct signals I/O-driven load, not CPU-bound work.
	IOwaitPct    float64 `json:"iowait_pct"`
	Status       string  `json:"status"`
	StatusReason string  `json:"status_reason"`
}
