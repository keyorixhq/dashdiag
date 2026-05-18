package models

// LogsInfo holds system log health data.
type LogsInfo struct {
	Available     bool     `json:"available"`               // false on non-Linux
	OOMKills      int      `json:"oom_kills"`               // OOM kills in last hour from /dev/kmsg
	OOMProcesses  []string `json:"oom_processes"`           // Names of killed processes
	Segfaults     int      `json:"segfaults"`               // Segfaults in last hour from /dev/kmsg
	SegfaultProcs []string `json:"segfault_procs"`          // Names of faulting processes
	SoftLockups   int      `json:"soft_lockups"`            // kernel: BUG: soft lockup events
	HardLockups   int      `json:"hard_lockups"`            // NMI watchdog: BUG: hard lockup events
	KernelPanics  int      `json:"kernel_panics"`           // Kernel panic events from pstore or kmsg
	NVMeTimeouts  int      `json:"nvme_timeouts,omitempty"` // NVMe I/O timeout events from kmsg
	NVMeResets    int      `json:"nvme_resets,omitempty"`   // NVMe controller reset/down events from kmsg
	JournalSizeGB float64  `json:"journal_size_gb"`
	CrashLoops    []string `json:"crash_loops"`
	NeedsRoot     bool     `json:"needs_root,omitempty"`

	// Journal health
	JournalCorrupt        bool    `json:"journal_corrupt,omitempty"`          // journalctl --verify failed
	JournalVolatile       bool    `json:"journal_volatile,omitempty"`         // logs lost on reboot
	JournalRateLimited    bool    `json:"journal_rate_limited,omitempty"`     // RateLimitBurst too low
	JournalNoTextFallback bool    `json:"journal_no_text_fallback,omitempty"` // no rsyslog/syslog-ng
	JournalUnbounded      bool    `json:"journal_unbounded,omitempty"`        // no SystemMaxUse cap
	JournalSyncRisk       bool    `json:"journal_sync_risk,omitempty"`        // SyncIntervalSec too high, final logs may be lost
	LogDiskUsedPct        float64 `json:"log_disk_used_pct,omitempty"`        // % used on log volume
	LogDiskMount          string  `json:"log_disk_mount,omitempty"`           // mount point of log volume

	Status       string `json:"status,omitempty"`
	StatusReason string `json:"status_reason,omitempty"`
}
