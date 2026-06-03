package models

// ResolverLinkDNS holds the DNS configuration resolvectl reports for one link.
type ResolverLinkDNS struct {
	Link    string   `json:"link"`              // interface name, e.g. "eth0", "wg0"
	Servers []string `json:"servers,omitempty"` // DNS servers assigned to this link
	DNSSEC  string   `json:"dnssec,omitempty"`  // effective DNSSEC mode for this link
}

// ResolverAuditInfo is the output of the DNS resolver audit appended to
// `dsd net deep`. It is distinct from DNSResolverInfo (used by `dsd net dns`),
// which audits /etc/resolv.conf; this struct audits the systemd-resolved /
// NetworkManager resolver feature set, DNSSEC, DoT and VPN DNS routing.
type ResolverAuditInfo struct {
	Detected bool `json:"-"` // true when the section should render (always on Linux)

	// Resolver detection
	ResolverType     string `json:"resolver_type"`                // "systemd-resolved", "NetworkManager", "dnsmasq", "unbound", "static", "none"
	ResolverActive   bool   `json:"resolver_active"`              // resolver service is active
	ResolvConfMode   string `json:"resolv_conf_mode"`             // "stub", "uplink", "custom", "unknown"
	ResolvConfTarget string `json:"resolv_conf_target,omitempty"` // symlink target of /etc/resolv.conf

	// systemd-resolved feature set
	DNSSECConfigured     string            `json:"dnssec_configured,omitempty"`      // from resolved.conf: yes/no/allow-downgrade
	DNSSECActive         string            `json:"dnssec_active,omitempty"`          // effective from resolvectl status
	DNSSECDegraded       bool              `json:"dnssec_degraded"`                  // configured yes but downgraded in practice
	DNSSECDegradedReason string            `json:"dnssec_degraded_reason,omitempty"` // human reason for the downgrade
	DoTStatus            string            `json:"dot_status,omitempty"`             // DNS-over-TLS: yes/no/opportunistic
	LinkDNS              []ResolverLinkDNS `json:"link_dns,omitempty"`               // per-interface DNS from resolvectl

	// DNSSEC validation test (resolvectl query of a known-good signed domain)
	DNSSECTestRan    bool   `json:"dnssec_test_ran"`             // test was attempted
	DNSSECTestPassed bool   `json:"dnssec_test_passed"`          // domain validated (authenticated: yes)
	DNSSECTestError  string `json:"dnssec_test_error,omitempty"` // distinguishes SERVFAIL from timeout/no-internet

	// VPN DNS integration. nil = no VPN interface present (not applicable),
	// true = VPN link has DNS servers, false = VPN up but DNS not routed through it.
	VPNInterface     string `json:"vpn_interface,omitempty"`
	VPNDNSIntegrated *bool  `json:"vpn_dns_integrated"`

	// NetworkManager fallback path (RHEL with systemd-resolved disabled)
	NMNameservers []string `json:"nm_nameservers,omitempty"`
	FallbackNote  string   `json:"fallback_note,omitempty"`
}
