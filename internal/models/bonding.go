package models

// BondSlave is one physical NIC enslaved to a bond interface.
type BondSlave struct {
	Name      string `json:"name"`
	State     string `json:"state"`      // up, down
	MIIStatus string `json:"mii_status"` // MII Status: up/down
	SpeedMbps int    `json:"speed_mbps,omitempty"`
	Duplex    string `json:"duplex,omitempty"`
	LinkFails int    `json:"link_failures,omitempty"`
	// 802.3ad only: aggregator the slave joined. Slaves that fail to negotiate land
	// in different aggregators (or their own), so a split here means LACP isn't bundling.
	AggregatorID int `json:"aggregator_id,omitempty"`
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
	// 802.3ad (LACP) aggregation state. A bond can have every slave MII-up yet carry no
	// traffic if LACP never negotiated — a green-but-dead bond the MII check misses.
	PartnerMAC      string `json:"partner_mac,omitempty"`      // LACP partner system MAC (all-zero = no partner heard)
	AggregatorPorts int    `json:"aggregator_ports,omitempty"` // ports in the active aggregator
	NotAggregating  bool   `json:"not_aggregating"`            // 802.3ad: slaves MII-up but LACP not aggregating
}

// BondingInfo holds all bond interfaces found on the host.
type BondingInfo struct {
	Bonds        []BondInterface `json:"bonds"`
	Status       string          `json:"status,omitempty"`
	StatusReason string          `json:"status_reason,omitempty"`
}
