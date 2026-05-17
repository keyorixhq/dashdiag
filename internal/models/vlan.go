package models

// VLANInterface is one VLAN-tagged interface.
type VLANInterface struct {
	Name   string `json:"name"`   // e.g. eth0.100
	Parent string `json:"parent"` // e.g. eth0
	VLANID int    `json:"vlan_id"`
	Up     bool   `json:"up"`
}

// VLANInfo holds VLAN interface health.
type VLANInfo struct {
	Interfaces   []VLANInterface `json:"interfaces,omitempty"`
	Status       string          `json:"status,omitempty"`
	StatusReason string          `json:"status_reason,omitempty"`
}
