package models

// MultipathPath is one physical path to a multipath device.
type MultipathPath struct {
	Device string `json:"device"` // e.g. sdb, sdc
	State  string `json:"state"`  // active, failed, shaky, ghost, undef
	DM     string `json:"dm"`     // dm-0, dm-1
}

// MultipathDevice is one logical multipath device (dm-N / wwid).
type MultipathDevice struct {
	Name        string          `json:"name"`  // WWID or alias
	DM          string          `json:"dm"`    // dm-0
	State       string          `json:"state"` // active, failed
	ActivePaths int             `json:"active_paths"`
	FailedPaths int             `json:"failed_paths"`
	TotalPaths  int             `json:"total_paths"`
	Paths       []MultipathPath `json:"paths,omitempty"`
}

// MultipathInfo holds DM-MPIO multipath health data.
type MultipathInfo struct {
	Available    bool              `json:"available"`
	Devices      []MultipathDevice `json:"devices,omitempty"`
	Status       string            `json:"status,omitempty"`
	StatusReason string            `json:"status_reason,omitempty"`
}
