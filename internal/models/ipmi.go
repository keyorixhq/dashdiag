package models

// IPMISensor is one row from ipmitool sdr.
type IPMISensor struct {
	Name   string  `json:"name"`
	Value  float64 `json:"value"`
	Unit   string  `json:"unit"`
	Status string  `json:"status"` // ok, ns (not specified), nc (non-critical), cr (critical), nr (non-recoverable), na
}

// IPMIInfo holds IPMI/BMC sensor data.
type IPMIInfo struct {
	Available    bool         `json:"available"`
	Sensors      []IPMISensor `json:"sensors,omitempty"`
	PSUFailed    int          `json:"psu_failed,omitempty"`
	FanFailed    int          `json:"fan_failed,omitempty"`
	TempCritical int          `json:"temp_critical,omitempty"` // count of sensors in critical temp state
	Status       string       `json:"status,omitempty"`
	StatusReason string       `json:"status_reason,omitempty"`
}
