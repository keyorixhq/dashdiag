package models

// CPUFreqInfo holds CPU frequency scaling state.
type CPUFreqInfo struct {
	Governor     string  `json:"governor"` // performance, powersave, schedutil, ondemand
	CurrentMHz   int     `json:"current_mhz"`
	MaxMHz       int     `json:"max_mhz"`
	MinMHz       int     `json:"min_mhz"`
	ThrottledPct float64 `json:"throttled_pct"` // (max - current) / max * 100
	CPUCount     int     `json:"cpu_count"`
	// HasBattery is true when the host has a battery (laptop / handheld like the
	// Steam Deck). On such portable devices 'powersave' is the correct, deliberate
	// governor, not a server misconfiguration — so the analysis layer downgrades
	// the "performance limited" WARN to INFO.
	HasBattery   bool   `json:"has_battery,omitempty"`
	Status       string `json:"status,omitempty"`
	StatusReason string `json:"status_reason,omitempty"`
}
