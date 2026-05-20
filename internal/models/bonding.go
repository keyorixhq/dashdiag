package models

// BondSlave is one physical NIC enslaved to a bond interface.
type BondSlave struct {
	Name      string `json:"name"`
	State     string `json:"state"`      // up, down
	MIIStatus string `json:"mii_status"` // MII Status: up/down
	SpeedMbps int    `json:"speed_mbps,omitempty"`
	Duplex    string `json:"duplex,omitempty"`
	LinkFails int    `json:"link_failures,omitempty"`
}

// BondInterface is one logical bond (bond0, bond1, …).
type BondInterface struct {
	Name        string      `json:"name"`
	Mode        string      `json:"mode"`                   // e.g. "IEEE 802.3ad Dynamic link aggregation"
	ModeShort   string      `json:"mode_short"`             // e.g. "802.3ad", "active-backup"
	MIIStatus   string      `json:"mii_status"`             // "up" / "down"
	ActiveSlave string      `json:"active_slave,omitempty"` // active-backup only
	Slaves      []BondSlave `json:"slaves"`
	DownSlaves  int         `json:"down_slaves"` // count of slaves that are down
	Degraded    bool        `json:"degraded"`    // true if any slave is down
	AllDown     bool        `json:"all_down"`    // true if all slaves down
}

// BondingInfo holds all bond interfaces found on the host.
type BondingInfo struct {
	Bonds        []BondInterface `json:"bonds"`
	Status       string          `json:"status,omitempty"`
	StatusReason string          `json:"status_reason,omitempty"`
}
