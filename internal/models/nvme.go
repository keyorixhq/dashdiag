package models

// NVMeDevice holds SMART health data for a single NVMe drive.
type NVMeDevice struct {
	Name              string   `json:"name"`
	Model             string   `json:"model"`
	State             string   `json:"state"`
	TempC             float64  `json:"temp_c"`
	AvailableSparePct int      `json:"available_spare_pct"`
	SpareThresholdPct int      `json:"spare_threshold_pct"`
	PercentageUsed    int      `json:"percentage_used"`
	CriticalWarning   int      `json:"critical_warning"`
	MediaErrors       int64    `json:"media_errors"`
	UnsafeShutdowns   int64    `json:"unsafe_shutdowns"`
	PowerOnHours      int64    `json:"power_on_hours"`
	PowerCycles       int64    `json:"power_cycles"`
	MountPoints       []string `json:"mount_points,omitempty"` // empty = unmounted
	HasLinux          bool     `json:"has_linux"`              // has mounted Linux fs
}

// NVMeInfo holds health data for all NVMe drives.
type NVMeInfo struct {
	Devices      []NVMeDevice `json:"devices"`
	Status       string       `json:"status,omitempty"`
	StatusReason string       `json:"status_reason,omitempty"`
}
