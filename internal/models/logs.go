package models

// LogsInfo holds system log health data.
type LogsInfo struct {
	OOMKills      int      `json:"oom_kills"`      // OOM kills in last hour from /dev/kmsg
	OOMProcesses  []string `json:"oom_processes"`  // Names of killed processes
	Segfaults     int      `json:"segfaults"`      // Segfaults in last hour from /dev/kmsg
	SegfaultProcs []string `json:"segfault_procs"` // Names of faulting processes
	SoftLockups   int      `json:"soft_lockups"`   // kernel: BUG: soft lockup events
	HardLockups   int      `json:"hard_lockups"`   // NMI watchdog: BUG: hard lockup events
	KernelPanics  int      `json:"kernel_panics"`  // Kernel panic events from pstore or kmsg
	JournalSizeGB float64  `json:"journal_size_gb"`
	CrashLoops    []string `json:"crash_loops"`
	NeedsRoot     bool     `json:"needs_root,omitempty"` // kmsg and auth logs require root
	Status        string   `json:"status,omitempty"`
	StatusReason  string   `json:"status_reason,omitempty"`
}
