package models

type FDProcessInfo struct {
	PID       int     `json:"pid"`
	Name      string  `json:"name"`
	OpenFDs   int     `json:"open_fds"`
	SoftLimit int     `json:"soft_limit"`
	UsedPct   float64 `json:"used_pct"`
	// SoftLimitUnlimited is true when RLIMIT_NOFILE's soft limit is "unlimited"
	// (SoftLimit carries the math.MaxInt32 sentinel). UsedPct against an
	// unlimited limit is always ~0% regardless of OpenFDs, so a process is
	// flagged hot here on an absolute OpenFDs threshold instead — otherwise a
	// leaking process with an unlimited rlimit could never appear in the
	// hot-process list no matter how many descriptors it held.
	SoftLimitUnlimited bool `json:"soft_limit_unlimited,omitempty"`
}

type FDInfo struct {
	OpenCount         uint64          `json:"open_count"`
	MaxCount          uint64          `json:"max_count"`
	UsedPct           float64         `json:"used_pct"`
	HotProcesses      []FDProcessInfo `json:"hot_processes"`
	DeletedOpenFiles  int             `json:"deleted_open_files"`
	DeletedOpenSizeGB float64         `json:"deleted_open_size_gb"`
	Status            string          `json:"status"`
	StatusReason      string          `json:"status_reason"`
}
