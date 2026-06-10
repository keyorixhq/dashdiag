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
	MountPoints       []string `json:"mount_points,omitempty"`
	HasLinux          bool     `json:"has_linux"`
	// SmartRead is true only when the SMART log was actually read (nvme-cli
	// present). When false the device was detected via sysfs but its health
	// fields are zero-defaults — NOT a confirmed-healthy drive. Without this the
	// renderer/heuristic can't tell "verified healthy" from "never checked".
	SmartRead bool `json:"smart_read"`
}

// SATADevice holds SMART health data for a SATA/SAS drive.
type SATADevice struct {
	Name                string   `json:"name"`
	Model               string   `json:"model"`
	Type                string   `json:"type"` // sata, sas
	TempC               int      `json:"temp_c"`
	SmartOK             bool     `json:"smart_ok"`
	PowerOnHours        int64    `json:"power_on_hours"`
	ReallocatedSectors  int      `json:"reallocated_sectors"`
	PendingSectors      int      `json:"pending_sectors"`
	UncorrectableErrors int      `json:"uncorrectable_errors"`
	MountPoints         []string `json:"mount_points,omitempty"`
	Error               string   `json:"error,omitempty"`
}

// NVMeInfo holds health data for all drives (NVMe + SATA/SAS).
// Named NVMeInfo for backwards compatibility — now covers all drive types.
type NVMeInfo struct {
	Devices      []NVMeDevice `json:"devices"`
	SATADevices  []SATADevice `json:"sata_devices,omitempty"`
	Status       string       `json:"status,omitempty"`
	StatusReason string       `json:"status_reason,omitempty"`
}
