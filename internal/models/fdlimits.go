package models

type FDProcessInfo struct {
	PID       int     `json:"pid"`
	Name      string  `json:"name"`
	OpenFDs   int     `json:"open_fds"`
	SoftLimit int     `json:"soft_limit"`
	UsedPct   float64 `json:"used_pct"`
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
