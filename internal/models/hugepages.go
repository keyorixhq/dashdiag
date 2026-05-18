package models

// HugePagesInfo holds huge page configuration and usage from /proc/meminfo.
type HugePagesInfo struct {
	Available    bool    `json:"available"`
	Configured   int     `json:"configured"`   // HugePages_Total
	Free         int     `json:"free"`         // HugePages_Free
	Used         int     `json:"used"`         // Configured - Free
	PageSizeKB   int     `json:"page_size_kb"` // Hugepagesize in kB
	ReservedGB   float64 `json:"reserved_gb"`  // Configured * PageSizeKB / 1M
	THPEnabled   bool    `json:"thp_enabled"`  // transparent huge pages active
	THPMode      string  `json:"thp_mode"`     // always, madvise, never
	Status       string  `json:"status,omitempty"`
	StatusReason string  `json:"status_reason,omitempty"`
}
