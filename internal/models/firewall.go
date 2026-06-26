package models

// FirewallChain is one iptables/nftables chain.
type FirewallChain struct {
	Table  string `json:"table"`
	Name   string `json:"name"`
	Policy string `json:"policy"` // ACCEPT, DROP, REJECT
	Rules  int    `json:"rules"`
}

// FirewallInfo holds firewall state.
type FirewallInfo struct {
	Available   bool            `json:"available"`
	Backend     string          `json:"backend"` // iptables, nftables, ufw, firewalld
	Active      bool            `json:"active"`
	Chains      []FirewallChain `json:"chains,omitempty"`
	TotalRules  int             `json:"total_rules"`
	DefaultDrop bool            `json:"default_drop"` // INPUT policy is DROP/REJECT
	// PVEFirewallActive is true on Proxmox VE hosts where the pve-firewall
	// service is the active firewall manager. pve-firewall loads its rules
	// dynamically, so an empty base ruleset is not "unprotected".
	PVEFirewallActive bool `json:"pve_firewall_active,omitempty"`
	// CloudGuest is true when this host is a detected cloud VM (AWS/Azure/GCP),
	// where network filtering is typically enforced by the provider's Security
	// Group / NSG / VPC firewall — a layer dsd cannot see from inside the guest.
	// An empty host ruleset on such a guest is not asserted "unprotected".
	CloudGuest    bool   `json:"cloud_guest,omitempty"`
	CloudProvider string `json:"cloud_provider,omitempty"` // aws, azure, gcp
	Status        string `json:"status,omitempty"`
	StatusReason  string `json:"status_reason,omitempty"`
}
