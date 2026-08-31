package models

// NetworkdConfigInfo reports systemd-networkd configuration-file health.
// systemd-networkd runs as an unprivileged dynamic user and SILENTLY ignores any
// /etc/systemd/network/*.{network,link,netdev} file that is not readable by
// "other" (the documented requirement is mode 0644). An ignored .network file
// leaves the interface it configures unconfigured — a no-network state with no
// error printed to the console. VMware Photon OS (networkd by default, files
// often root-created at 0600) is the prime victim. Detected is false on
// non-networkd hosts, so the check renders nothing there.
type NetworkdConfigInfo struct {
	Detected        bool                 `json:"detected"`
	TotalFiles      int                  `json:"total_files"`
	UnreadableFiles []NetworkdConfigFile `json:"unreadable_files,omitempty"`
	// ConfigDirUnreadable is true when /etc/systemd/network itself could not
	// be read (a non-world-readable directory, e.g. 0750 root:systemd-network
	// on some hardened images) — distinct from TotalFiles==0/UnreadableFiles
	// being empty, which also means "genuinely no files here". Without this,
	// filepath.Glob's own permission-error swallowing (it returns an empty,
	// nil-error result on a directory it can't read) makes the two
	// indistinguishable — a permission audit reporting "0 unreadable files"
	// because it could not even see the files to audit.
	ConfigDirUnreadable bool `json:"config_dir_unreadable,omitempty"`
	// FailedLinks are managed links whose networkd SETUP (AdministrativeState)
	// is "failed" — networkd tried to apply their config and could not. A bad
	// .network directive, a conflicting address/route, or the unreadable-file
	// case above all surface here as the effect.
	FailedLinks []NetworkdLink `json:"failed_links,omitempty"`
	// StuckLinks are managed links still in SETUP=configuring/pending long after boot
	// (uptime-gated) — networkd never finished bringing them up (bad DHCP, an address
	// it can't apply, …). Distinct from FailedLinks: networkd hasn't given up, it's
	// stuck. The uptime gate keeps boot-time transients from showing here.
	StuckLinks []NetworkdLink `json:"stuck_links,omitempty"`
}

// NetworkdConfigFile is one config file systemd-networkd cannot read (wrong perms).
type NetworkdConfigFile struct {
	Path string `json:"path"`
	Mode string `json:"mode"` // octal permission bits, e.g. "0600"
}

// NetworkdLink is one systemd-networkd-managed link's state, from `networkctl`.
type NetworkdLink struct {
	Name        string `json:"name"`
	Setup       string `json:"setup"`       // AdministrativeState: configured/configuring/failed/unmanaged/…
	Operational string `json:"operational"` // OperationalState: routable/degraded/no-carrier/off/…
}
