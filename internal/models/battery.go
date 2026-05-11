package models

// BatteryInfo holds battery health data.
type BatteryInfo struct {
	Present         bool    `json:"present"`
	Status          string  `json:"status"`
	CapacityPct     int     `json:"capacity_pct"`
	HealthPct       float64 `json:"health_pct"`
	EnergyNowUWh    int64   `json:"energy_now_uwh"`
	EnergyFullUWh   int64   `json:"energy_full_uwh"`
	EnergyDesignUWh int64   `json:"energy_design_uwh"`
	CycleCounts     int     `json:"cycle_count"`
	VoltageUV       int64   `json:"voltage_uv"`
	PowerNowUW      int64   `json:"power_now_uw"`
	Manufacturer    string  `json:"manufacturer,omitempty"`
	ModelName       string  `json:"model_name,omitempty"`
	StatusReason    string  `json:"status_reason,omitempty"`
}
