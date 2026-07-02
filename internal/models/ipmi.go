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
	// NeedsRoot is true when a sensor read failed AND dsd is not running as
	// root — in-band IPMI reads the 0600 root:root BMC device, so a non-root
	// failure is expected and must not be reported as a real "sdr read failed"
	// error (unlike NVMe/ceph/hwraid, IPMI had no root check, so a non-root
	// `dsd health` WARNed on any physical server even when the BMC is healthy).
	NeedsRoot bool `json:"needs_root,omitempty"`
}
