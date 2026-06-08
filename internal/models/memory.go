package models

type MemoryInfo struct {
	TotalGB       float64 `json:"total_gb"`
	FreeGB        float64 `json:"free_gb"`
	UsedPct       float64 `json:"used_pct"`
	SlabMB        float64 `json:"slab_mb"`
	CommitLimitMB float64 `json:"commit_limit_mb"`
	CommittedAsMB float64 `json:"committed_as_mb"`
	OverCommitted bool    `json:"over_committed"`
	// OvercommitMode is vm.overcommit_memory: 0 = heuristic (default), 1 = always
	// overcommit, 2 = strict accounting. CommitLimit is only ENFORCED in mode 2,
	// so Committed_AS exceeding it is an OOM risk only there; in modes 0/1 it is
	// normal and must not be flagged.
	OvercommitMode int `json:"overcommit_mode"`
	// EDAC / ECC memory error counts (physical hosts only; zero on VMs/consumer
	// hardware where EDAC is unavailable). Surfaced in default `dsd health` so a
	// failing DIMM is caught without needing the heavier `dsd hardware`.
	EDACAvailable     bool  `json:"edac_available,omitempty"`
	CorrectedErrors   int64 `json:"corrected_ecc_errors,omitempty"`
	UncorrectedErrors int64 `json:"uncorrected_ecc_errors,omitempty"`

	Status       string `json:"status"`
	StatusReason string `json:"status_reason"`
}
