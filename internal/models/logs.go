package models

// CrashFile is a crash dump or core file found on disk.
type CrashFile struct {
	Path    string  `json:"path"`
	SizeMB  float64 `json:"size_mb"`
	AgeDays int     `json:"age_days"`
}

// TopError is a single ranked error entry with its source and age.
// AgeMin is -1 when the timestamp could not be parsed.
type TopError struct {
	Message string `json:"message"`
	Source  string `json:"source"`  // unit or process name (e.g. "kernel", "nginx")
	AgeMin  int    `json:"age_min"` // minutes since the event; -1 if unknown
}

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
	Virtualized   bool     `json:"virtualized,omitempty"`   // VM/cloud guest — NVMe is virtual storage, so timeouts are hypervisor/cloud events, not a failing physical drive
	JournalSizeGB float64  `json:"journal_size_gb"`
	CrashLoops    []string `json:"crash_loops"`
	NeedsRoot     bool     `json:"needs_root,omitempty"`

	// Journal health
	JournalCorrupt        bool    `json:"journal_corrupt,omitempty"`
	JournalVolatile       bool    `json:"journal_volatile,omitempty"`
	JournalRateLimited    bool    `json:"journal_rate_limited,omitempty"`
	JournalNoTextFallback bool    `json:"journal_no_text_fallback,omitempty"`
	JournalUnbounded      bool    `json:"journal_unbounded,omitempty"`
	JournalSyncRisk       bool    `json:"journal_sync_risk,omitempty"`
	LogDiskUsedPct        float64 `json:"log_disk_used_pct,omitempty"`
	LogDiskMount          string  `json:"log_disk_mount,omitempty"`

	// Severity summary (Spec 3 addition)
	ErrorCount   int        `json:"error_count"`            // ERR + CRIT + ALERT + EMERG in last hour
	WarningCount int        `json:"warning_count"`          // WARNING in last hour
	TopErrors    []string   `json:"top_errors,omitempty"`   // deduplicated top error messages (legacy)
	TopCritical  []TopError `json:"top_critical,omitempty"` // structured top errors with source + age

	// Crash files on disk (Spec 3 addition)
	CrashFiles    []CrashFile `json:"crash_files,omitempty"` // core dumps, crash reports
	CoreDumpCount int         `json:"core_dump_count"`       // total coredumps found

	// Log source used for this run
	LogSource string `json:"log_source,omitempty"` // "journald", "journald+syslog", "syslog"

	Status       string `json:"status,omitempty"`
	StatusReason string `json:"status_reason,omitempty"`
}
