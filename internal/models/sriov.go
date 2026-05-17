package models

// SRIOVDevice is one PCI device with SR-IOV capability.
type SRIOVDevice struct {
	PCI      string `json:"pci"`       // 0000:01:00.0
	Driver   string `json:"driver"`    // mlx5_core, i40e, etc.
	NumVFs   int    `json:"num_vfs"`   // currently active VFs
	TotalVFs int    `json:"total_vfs"` // maximum VFs supported
}

// SRIOVInfo holds SR-IOV virtual function state.
type SRIOVInfo struct {
	Devices      []SRIOVDevice `json:"devices,omitempty"`
	Status       string        `json:"status,omitempty"`
	StatusReason string        `json:"status_reason,omitempty"`
}
