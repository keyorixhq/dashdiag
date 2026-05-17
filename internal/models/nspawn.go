package models

// NspawnContainer is one systemd-nspawn container.
type NspawnContainer struct {
	Name    string `json:"name"`
	State   string `json:"state"` // running, degraded, exited
	Machine string `json:"machine,omitempty"`
}

// NspawnInfo holds systemd-nspawn container health.
type NspawnInfo struct {
	Available    bool              `json:"available"`
	Containers   []NspawnContainer `json:"containers,omitempty"`
	FailedCount  int               `json:"failed_count,omitempty"`
	Status       string            `json:"status,omitempty"`
	StatusReason string            `json:"status_reason,omitempty"`
}
