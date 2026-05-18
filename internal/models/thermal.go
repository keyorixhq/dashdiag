package models

// ThermalInfo holds CPU and system temperature data.
type ThermalInfo struct {
	Available    bool               `json:"available"`
	CPUTempC     float64            `json:"cpu_temp_c"`
	CoreTemps    map[string]float64 `json:"core_temps,omitempty"`
	Source       string             `json:"source"` // hwmon driver name or "battery-proxy" on macOS
	Status       string             `json:"status,omitempty"`
	StatusReason string             `json:"status_reason,omitempty"`
}
