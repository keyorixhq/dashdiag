package models

type FilesystemInfo struct {
	Mount         string  `json:"mount"`
	Device        string  `json:"device"`
	FSType        string  `json:"fs_type"`
	TotalGB       float64 `json:"total_gb"`
	UsedGB        float64 `json:"used_gb"`
	FreeGB        float64 `json:"free_gb"`
	UsedPct       float64 `json:"used_pct"`
	InodesUsedPct float64 `json:"inodes_used_pct"`
	ReadOnly      bool    `json:"read_only"`
	Status        string  `json:"status"`
	StatusReason  string  `json:"status_reason"`
}

type DiskInfo struct {
	Filesystems  []FilesystemInfo `json:"filesystems"`
	Status       string           `json:"status"`
	StatusReason string           `json:"status_reason"`
}
