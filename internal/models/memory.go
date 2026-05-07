package models

type MemoryInfo struct {
	TotalGB       float64 `json:"total_gb"`
	FreeGB        float64 `json:"free_gb"`
	UsedPct       float64 `json:"used_pct"`
	SlabMB        float64 `json:"slab_mb"`
	CommitLimitMB float64 `json:"commit_limit_mb"`
	CommittedAsMB float64 `json:"committed_as_mb"`
	OverCommitted bool    `json:"over_committed"`
	Status        string  `json:"status"`
	StatusReason  string  `json:"status_reason"`
}
