package models

// WiFiInfo holds wireless interface health data.
type WiFiInfo struct {
	SSID      string  `json:"ssid,omitempty"`
	BSSID     string  `json:"bssid,omitempty"`
	SignalDBm int     `json:"signal_dbm,omitempty"` // e.g. -30 (higher = better; >-50 excellent)
	SignalPct int     `json:"signal_pct,omitempty"` // 0-100 from nmcli
	RateMbps  int     `json:"rate_mbps,omitempty"`  // current tx rate
	Channel   int     `json:"channel,omitempty"`
	FreqGHz   float64 `json:"freq_ghz,omitempty"`
	Band      string  `json:"band,omitempty"` // "2.4GHz" or "5GHz"
	Driver    string  `json:"driver,omitempty"`
}

type InterfaceInfo struct {
	Name      string    `json:"name"`
	IP        string    `json:"ip"`
	Up        bool      `json:"up"`
	RxDrops   uint64    `json:"rx_drops"`
	TxDrops   uint64    `json:"tx_drops"`
	RxErrors  uint64    `json:"rx_errors,omitempty"`
	TxErrors  uint64    `json:"tx_errors,omitempty"`
	SpeedMbps int       `json:"speed_mbps"`
	IsUSB     bool      `json:"is_usb,omitempty"`
	Driver    string    `json:"driver,omitempty"`
	WiFi      *WiFiInfo `json:"wifi,omitempty"` // non-nil for wireless interfaces
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
	// Deep metrics (populated by NetworkDeepCollector)
	TimeWaitCount    int             `json:"time_wait_count,omitempty"`    // TIME_WAIT sockets
	SynRetransCount  int             `json:"syn_retrans_count,omitempty"`  // TCPSynRetrans — SYN retransmissions
	ListenOverflows  int             `json:"listen_overflows,omitempty"`   // ListenOverflows — SYN backlog saturation
	RetransFailCount int             `json:"retrans_fail_count,omitempty"` // TCPRetransFail — persistent retransmit failures
	ConntrackUsedPct float64         `json:"conntrack_used_pct,omitempty"` // nf_conntrack fill %
	Status           string          `json:"status"`
	StatusReason     string          `json:"status_reason"`
	Bonds            []BondInterface `json:"bonds,omitempty"`
}
