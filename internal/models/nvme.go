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
	// SmartUnreadReason classifies WHY SmartRead is false so the heuristic gives
	// the correct remediation instead of a blanket "nvme-cli not installed":
	// "needs_root" (the smart-log ioctl is root-gated — the common non-root
	// case), "tool_absent" (nvme-cli genuinely missing), or "error" (present and
	// privileged but the read still failed). Empty when SmartRead is true.
	SmartUnreadReason string `json:"smart_unread_reason,omitempty"`
}

// SATADevice holds SMART health data for a SATA/SAS drive.
type SATADevice struct {
	Name  string `json:"name"`
	Model string `json:"model"`
	Type  string `json:"type"` // sata, sas
	TempC int    `json:"temp_c"`
	// SmartRead is true only when smartctl actually reported a SMART verdict
	// (smart_status.passed present). False when the drive was detected but SMART
	// couldn't be read — USB bridges, RAID/HBA controllers, virtual disks all
	// make `smartctl --json -a` emit JSON with no smart_status. Without this, a
	// missing verdict defaulted SmartOK=false and fired a false "drive may be
	// failing" CRIT (sibling of the NVMe SmartRead guard, BUG-048).
	SmartRead bool `json:"smart_read"`
	// SmartUnreadReason classifies WHY SMART was not read when SmartRead is false,
	// so the analysis layer gives an accurate remediation instead of lumping every
	// cause under "running unprivileged". One of: "needs_root" (smartctl hit a
	// permission error — re-run as root), "no_smart" (smartctl ran but the device
	// exposes no smart_status: virtual disk, USB bridge, RAID/HBA member), "error"
	// (smartctl failed to run). Empty on older captures. Recorded (not derived from
	// a live euid) so replay stays faithful — mirrors the NVMe field above.
	SmartUnreadReason   string   `json:"smart_unread_reason,omitempty"`
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
