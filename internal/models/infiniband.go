package models

// IBPort is one InfiniBand port.
type IBPort struct {
	Device string `json:"device"` // mlx5_0, ib0, etc.
	Port   int    `json:"port"`
	State  string `json:"state"` // ACTIVE, INIT, DOWN, POLLING
	Speed  string `json:"speed"` // HDR, EDR, FDR, QDR, etc.
	Width  string `json:"width"` // 4x, 1x, etc.
}

// InfiniBandInfo holds IB fabric health.
type InfiniBandInfo struct {
	Ports        []IBPort `json:"ports,omitempty"`
	Status       string   `json:"status,omitempty"`
	StatusReason string   `json:"status_reason,omitempty"`
}
