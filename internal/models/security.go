package models

// SecurityInfo holds system security posture data.
type SecurityInfo struct {
	// SSH configuration
	SSHPermitRoot   bool `json:"ssh_permit_root"`
	SSHPasswordAuth bool `json:"ssh_password_auth"`
	SSHRootLogin    bool `json:"ssh_root_login"`

	// Authentication
	FailedLogins   int      `json:"failed_logins"`    // failed logins in last hour
	FailedLoginIPs []string `json:"failed_login_ips"` // source IPs with most failures

	// Network exposure
	ListeningPorts []PortEntry `json:"listening_ports,omitempty"`
	PortsNeedRoot  bool        `json:"ports_need_root,omitempty"` // true when process names unavailable

	// Firewall
	FirewallActive   bool     `json:"firewall_active"`             // any firewall running
	FirewallType     string   `json:"firewall_type,omitempty"`     // firewalld, ufw, nftables, iptables
	FirewallZone     string   `json:"firewall_zone,omitempty"`     // active zone (firewalld only)
	FirewallServices []string `json:"firewall_services,omitempty"` // allowed services
	SSHAllowed       bool     `json:"ssh_allowed"`                 // SSH reachable through firewall

	// Privilege escalation
	SudoNopasswd []string `json:"sudo_nopasswd,omitempty"` // users/groups with NOPASSWD
	SUIDBinaries []string `json:"suid_binaries,omitempty"` // unexpected SUID binaries
	UID0Users    []string `json:"uid0_users,omitempty"`    // non-root users with UID 0
	SuspectCrons []string `json:"suspect_crons,omitempty"` // cron jobs writing to sensitive paths

	// AppArmor (SLES/Ubuntu/Debian)
	AppArmorMode     string `json:"apparmor_mode,omitempty"`     // enforce, complain, disabled
	AppArmorProfiles int    `json:"apparmor_profiles,omitempty"` // total loaded profiles
	AppArmorComplain int    `json:"apparmor_complain,omitempty"` // profiles in complain mode
	AppArmorDenials  int    `json:"apparmor_denials,omitempty"`  // denials in last hour

	// SELinux
	SELinuxDenials int    `json:"se_linux_denials"` // denials in last hour
	SELinuxMode    string `json:"se_linux_mode"`

	// RHEL/Rocky-specific security
	FIPSEnabled     bool   `json:"fips_enabled"`            // /proc/sys/crypto/fips_enabled
	CryptoPolicy    string `json:"crypto_policy,omitempty"` // DEFAULT, FIPS, FUTURE, LEGACY
	USBGuardActive  bool   `json:"usb_guard_active"`        // usbguard service running
	AIDEInstalled   bool   `json:"aide_installed"`          // aide binary present
	AIDEDBExists    bool   `json:"aide_db_exists"`          // /var/lib/aide/aide.db exists
	AIDELastRunDays int    `json:"aide_last_run_days"`      // days since last aide check (-1 = never)
	AuditRules      int    `json:"audit_rules"`             // number of active auditd rules (-1 = unavailable)

	// SUSE-specific: supportconfig diagnostic tool
	SupportconfigAvailable   bool   `json:"supportconfig_available"`         // supportutils package installed
	SupportconfigLastRunDays int    `json:"supportconfig_last_run_days"`     // days since last archive (-1 = never)
	SupportconfigArchive     string `json:"supportconfig_archive,omitempty"` // path to most recent archive

	// SUSEConnect subscription
	SUSEConnectRegistered  bool   `json:"suseconnect_registered,omitempty"`
	SUSEConnectExpiresDays int    `json:"suseconnect_expires_days,omitempty"` // days until expiry (-1 = unknown, 0 = expired)
	SUSEConnectStatus      string `json:"suseconnect_status,omitempty"`       // ACTIVE, EXPIRED, evaluation

	Status       string `json:"status,omitempty"`
	StatusReason string `json:"status_reason,omitempty"`
	NeedsRoot    bool   `json:"needs_root,omitempty"` // some checks require root

	// Offensive/pentest distro flag — suppresses false-positive WARNs for
	// intentionally relaxed defaults (e.g. Kali Linux root SSH, no firewall).
	IsOffensiveDistro bool `json:"is_offensive_distro,omitempty"`
}

// PortEntry describes a listening network port.
type PortEntry struct {
	Port     int    `json:"port"`
	Protocol string `json:"protocol"`
	Process  string `json:"process"`
	Expected bool   `json:"expected"`
}

// SnapperInfo holds Btrfs/Snapper snapshot health for SLES/openSUSE.
type SnapperInfo struct {
	Available     bool    `json:"available"`
	ConfigCount   int     `json:"config_count"`
	SnapshotCount int     `json:"snapshot_count"`
	OldestDays    int     `json:"oldest_days"`     // age of oldest snapshot
	TotalSpaceGB  float64 `json:"total_space_gb"`  // total space used by snapshots
	LastSnapshotH int     `json:"last_snapshot_h"` // hours since last snapshot (-1 = none)
	Error         string  `json:"error,omitempty"`
}

// SUSEConnectInfo holds subscription state for enterprise Linux systems.
// Covers SUSE (SUSEConnect), RHEL/Oracle/Rocky (subscription-manager),
// and Ubuntu Pro (pro status).
type SUSEConnectInfo struct {
	Platform    string `json:"platform"` // "suse", "rhel", "ubuntu-pro"
	Registered  bool   `json:"registered"`
	ExpiresDays int    `json:"expires_days"` // -1=unknown, 0=expired, >0=days remaining
	Status      string `json:"status"`       // ACTIVE, EXPIRED, evaluation, attached, detached
}
