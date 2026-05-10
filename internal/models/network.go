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
	Interfaces            []InterfaceInfo `json:"interfaces"`
	PrimaryInterface      string          `json:"primary_interface,omitempty"`
	PrimaryInterfaceDown  bool            `json:"primary_interface_down,omitempty"`
	GatewayPingMs         float64         `json:"gateway_ping_ms"`
	InternetPingMs        float64         `json:"internet_ping_ms"`
	DNSResolvesMs         float64         `json:"dns_resolves_ms"`
	DNSFailed             bool            `json:"dns_failed,omitempty"`
	GatewayPacketLossPct  float64         `json:"gateway_packet_loss_pct,omitempty"`
	InternetPacketLossPct float64         `json:"internet_packet_loss_pct,omitempty"`
	JitterMs              float64         `json:"jitter_ms,omitempty"`
	CloseWaitCount        int             `json:"close_wait_count"`
	NATDetected           bool            `json:"nat_detected"`
	ICMPBlocked           bool            `json:"icmp_blocked,omitempty"` // ICMP unavailable (e.g. no CAP_NET_RAW); TCP fallback used
	Status                string          `json:"status"`
	StatusReason          string          `json:"status_reason"`
}
