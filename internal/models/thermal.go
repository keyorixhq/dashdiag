package models

// ThermalInfo holds CPU and system temperature data.
type ThermalInfo struct {
	CPUTempC     float64            `json:"cpu_temp_c"`
	CoreTemps    map[string]float64 `json:"core_temps,omitempty"`
	Source       string             `json:"source"` // hwmon driver name
	Status       string             `json:"status,omitempty"`
	StatusReason string             `json:"status_reason,omitempty"`
}
