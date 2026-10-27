package models

type SwapInfo struct {
	TotalGB          float64 `json:"total_gb"`
	UsedGB           float64 `json:"used_gb"`
	UsedPct          float64 `json:"used_pct"`
	PagesInPerSec    float64 `json:"pages_in_per_sec"`
	PagesOutPerSec   float64 `json:"pages_out_per_sec"`
	ZramDevices      int     `json:"zram_devices"`
	ZramUsedPct      float64 `json:"zram_used_pct"`
	MemPressureLevel int     `json:"mem_pressure_level,omitempty"` // Darwin only: kern.memorystatus_vm_pressure_level (1=normal,2=warn,3=urgent,4=critical; -1=could not be measured)
	Status           string  `json:"status"`
	StatusReason     string  `json:"status_reason"`
	// SwapsUnreadable is true when /proc/swaps could not be opened or parsed, so
	// TotalGB/UsedGB/UsedPct of 0 mean "not measured", not "no swap in use".
	SwapsUnreadable bool `json:"swaps_unreadable,omitempty"`
	// ZramUnreadable is true when the zram device list or a device's disksize/
	// mm_stat could not be read, leaving ZramUsedPct a lower bound or 0.
	ZramUnreadable bool `json:"zram_unreadable,omitempty"`
}
