package models

// CPUFreqInfo holds CPU frequency scaling state.
type CPUFreqInfo struct {
	Governor     string  `json:"governor"` // performance, powersave, schedutil, ondemand
	CurrentMHz   int     `json:"current_mhz"`
	MaxMHz       int     `json:"max_mhz"`
	MinMHz       int     `json:"min_mhz"`
	ThrottledPct float64 `json:"throttled_pct"` // (max - current) / max * 100
	CPUCount     int     `json:"cpu_count"`
	Status       string  `json:"status,omitempty"`
	StatusReason string  `json:"status_reason,omitempty"`
}
