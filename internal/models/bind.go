package models

// BINDZone holds validation result for a single DNS zone.
type BINDZone struct {
	Name  string `json:"name"`
	File  string `json:"file,omitempty"`
	OK    bool   `json:"ok"`
	Error string `json:"error,omitempty"`
}

// BINDInfo holds BIND/named server health data.
type BINDInfo struct {
	Detected       bool       `json:"detected"` // named process found
	ServiceActive  bool       `json:"service_active"`
	Version        string     `json:"version,omitempty"`
	Uptime         string     `json:"uptime,omitempty"`
	ConfigFile     string     `json:"config_file"` // /etc/named.conf or /etc/bind/named.conf
	ConfigOK       bool       `json:"config_ok"`
	ConfigError    string     `json:"config_error,omitempty"`
	Port53TCP      bool       `json:"port_53_tcp"`
	Port53UDP      bool       `json:"port_53_udp"`
	QueryOK        bool       `json:"query_ok"`
	QueryLatencyMs int        `json:"query_latency_ms"`
	Zones          []BINDZone `json:"zones,omitempty"`
	ZonesFailed    int        `json:"zones_failed"`
	RNCDAvailable  bool       `json:"rndc_available"`
	QueryCount     int64      `json:"query_count,omitempty"`
}
