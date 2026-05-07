package models

type InterfaceInfo struct {
	Name      string `json:"name"`
	IP        string `json:"ip"`
	Up        bool   `json:"up"`
	RxDrops   uint64 `json:"rx_drops"`
	TxDrops   uint64 `json:"tx_drops"`
	SpeedMbps int    `json:"speed_mbps"`
}

type NetworkInfo struct {
	Interfaces     []InterfaceInfo `json:"interfaces"`
	GatewayPingMs  float64         `json:"gateway_ping_ms"`
	InternetPingMs float64         `json:"internet_ping_ms"`
	DNSResolvesMs  float64         `json:"dns_resolves_ms"`
	JitterMs       float64         `json:"jitter_ms,omitempty"`
	CloseWaitCount int             `json:"close_wait_count"`
	NATDetected    bool            `json:"nat_detected"`
	Status         string          `json:"status"`
	StatusReason   string          `json:"status_reason"`
}
