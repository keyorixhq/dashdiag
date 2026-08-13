package models

// HBAPort is one Fibre Channel host bus adapter port.
type HBAPort struct {
	Name         string `json:"name"`
	PortState    string `json:"port_state"`              // Online, Offline, Linkdown, etc.
	NodeName     string `json:"node_name,omitempty"`     // WWN
	PortName     string `json:"port_name,omitempty"`     // WWPN
	FabricName   string `json:"fabric_name,omitempty"`   // fabric WWN
	SpeedGbps    int    `json:"speed_gbps,omitempty"`    // negotiated speed
	LinkFailures int    `json:"link_failures,omitempty"` // from /sys stats
	LossOfSync   int    `json:"loss_of_sync,omitempty"`
	LossOfSignal int    `json:"loss_of_signal,omitempty"`
	// CountersUnreadable is true when one or more of LinkFailures/LossOfSync/
	// LossOfSignal could not be read from sysfs — distinct from a genuinely
	// quiet fabric with real zero counts. Without this, an unreadable
	// statistics/*_count file (readSysfsHexInt returns 0 on any read failure)
	// is indistinguishable from "checked, zero link failures".
	CountersUnreadable bool   `json:"counters_unreadable,omitempty"`
	Driver             string `json:"driver,omitempty"` // lpfc, qla2xxx, etc.
}

// HBAInfo holds Fibre Channel HBA health data.
type HBAInfo struct {
	Ports        []HBAPort `json:"ports,omitempty"`
	Status       string    `json:"status,omitempty"`
	StatusReason string    `json:"status_reason,omitempty"`
}
