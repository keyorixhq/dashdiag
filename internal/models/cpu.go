package models

type CPUInfo struct {
	LoadAvg1     float64 `json:"load_avg_1"`
	LoadAvg5     float64 `json:"load_avg_5"`
	LoadAvg15    float64 `json:"load_avg_15"`
	NumCPU       int     `json:"num_cpu"`
	UsagePct     float64 `json:"usage_pct"`
	LoadPct      float64 `json:"load_pct"`
	Status       string  `json:"status"`
	StatusReason string  `json:"status_reason"`
}
