package models

// DNSResolverInfo is the output of the DNS resolver audit (`dsd net deep`).
type DNSResolverInfo struct {
	// Configuration source
	Manager    string `json:"manager"`     // "systemd-resolved", "NetworkManager", "static", "none"
	ConfigFile string `json:"config_file"` // /etc/resolv.conf path (or symlink target)
	StubMode   bool   `json:"stub_mode"`   // true when resolv.conf points to 127.0.0.53

	// Configured resolvers
	Nameservers   []string `json:"nameservers,omitempty"`
	SearchDomains []string `json:"search_domains,omitempty"`
	Options       []string `json:"options,omitempty"` // e.g. "ndots:5", "timeout:2"

	// Functionality tests
	ExternalResolvesOK bool   `json:"external_resolves_ok"` // can resolve google.com
	InternalResolvesOK bool   `json:"internal_resolves_ok"` // can resolve hostname itself
	ExternalLatencyMs  int    `json:"external_latency_ms"`
	ResolvTestError    string `json:"resolve_test_error,omitempty"`

	// Quality flags
	TooManyNameservers  bool     `json:"too_many_nameservers"` // >3 = libc silently drops extras
	HasLoopback         bool     `json:"has_loopback"`         // 127.x but not stub (misconfigured)
	NdotsHigh           int      `json:"ndots_high"`           // ndots value if >3 (Kubernetes hazard)
	DuplicateNameserver []string `json:"duplicate_nameserver,omitempty"`
	IPv6Only            bool     `json:"ipv6_only"`       // all resolvers are IPv6 (no IPv4 fallback)
	PublicFallback      bool     `json:"public_fallback"` // 8.8.8.8/1.1.1.1 in list (privacy flag)
}
