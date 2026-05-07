package models

type SwapInfo struct {
	TotalGB        float64 `json:"total_gb"`
	UsedGB         float64 `json:"used_gb"`
	UsedPct        float64 `json:"used_pct"`
	PagesInPerSec  float64 `json:"pages_in_per_sec"`
	PagesOutPerSec float64 `json:"pages_out_per_sec"`
	ZramDevices    int     `json:"zram_devices"`
	ZramUsedPct    float64 `json:"zram_used_pct"`
	Status         string  `json:"status"`
	StatusReason   string  `json:"status_reason"`
}
