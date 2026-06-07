package models

type MemoryInfo struct {
	TotalGB       float64 `json:"total_gb"`
	FreeGB        float64 `json:"free_gb"`
	UsedPct       float64 `json:"used_pct"`
	SlabMB        float64 `json:"slab_mb"`
	CommitLimitMB float64 `json:"commit_limit_mb"`
	CommittedAsMB float64 `json:"committed_as_mb"`
	OverCommitted bool    `json:"over_committed"`
	// EDAC / ECC memory error counts (physical hosts only; zero on VMs/consumer
	// hardware where EDAC is unavailable). Surfaced in default `dsd health` so a
	// failing DIMM is caught without needing the heavier `dsd hardware`.
	EDACAvailable     bool  `json:"edac_available,omitempty"`
	CorrectedErrors   int64 `json:"corrected_ecc_errors,omitempty"`
	UncorrectedErrors int64 `json:"uncorrected_ecc_errors,omitempty"`

	Status       string `json:"status"`
	StatusReason string `json:"status_reason"`
}
