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
	Ports []IBPort `json:"ports,omitempty"`
	// ReadFailed is true when /sys/class/infiniband could not be read for a
	// reason other than "does not exist" (e.g. a restricted container /sys
	// view) — Ports is then empty because nothing was enumerated, not because
	// no IB hardware is present. Never let that read as a clean "no IB".
	ReadFailed   bool   `json:"read_failed,omitempty"`
	Status       string `json:"status,omitempty"`
	StatusReason string `json:"status_reason,omitempty"`
}
