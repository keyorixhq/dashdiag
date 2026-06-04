package models

type CPUInfo struct {
	LoadAvg1  float64 `json:"load_avg_1"`
	LoadAvg5  float64 `json:"load_avg_5"`
	LoadAvg15 float64 `json:"load_avg_15"`
	NumCPU    int     `json:"num_cpu"`
	UsagePct  float64 `json:"usage_pct"`
	LoadPct   float64 `json:"load_pct"`
	// StealPct is the percentage of CPU time stolen by the hypervisor.
	// Non-zero only on virtual machines. > 10% indicates host over-provisioning.
	StealPct float64 `json:"steal_pct"`
	// IOwaitPct is the percentage of time the CPU was idle waiting for I/O.
	// High iowait (> 20%) with high load_pct signals I/O-driven load, not CPU-bound work.
	IOwaitPct float64 `json:"iowait_pct"`
	// RunQueue is the number of currently runnable processes (procs_running from
	// /proc/stat) at sample time. Sustained above NumCPU means tasks are queued
	// waiting for CPU — run-queue saturation. Distinct from UsagePct (how busy
	// cores are) and LoadAvg (which also counts D-state tasks). 0 on non-Linux.
	RunQueue int `json:"run_queue"`
	// ProcsBlocked is the number of processes in uninterruptible sleep (D state),
	// blocked on I/O (procs_blocked from /proc/stat). Complements IOwaitPct.
	ProcsBlocked int `json:"procs_blocked"`
	// ContextSwitchRate is context switches per second over the sample window
	// (delta of /proc/stat ctxt). Very high rates relative to baseline indicate
	// scheduling thrashing; reliable spike detection needs the history-aware v2.
	ContextSwitchRate float64 `json:"context_switch_rate"`
	Status            string  `json:"status"`
	StatusReason      string  `json:"status_reason"`
}
