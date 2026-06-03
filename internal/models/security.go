package models

// SecurityInfo holds system security posture data.
type SecurityInfo struct {
	// SSH configuration
	SSHPermitRoot          bool     `json:"ssh_permit_root"`
	SSHPasswordAuth        bool     `json:"ssh_password_auth"`
	SSHRootLogin           bool     `json:"ssh_root_login"`
	SSHPort                int      `json:"ssh_port,omitempty"`                   // non-standard port (0 = default 22)
	SSHProtocol1           bool     `json:"ssh_protocol1,omitempty"`              // Protocol 1 enabled (dangerous)
	SSHMaxAuthTries        int      `json:"ssh_max_auth_tries,omitempty"`         // 0 = not set / default
	SSHLoginGraceTime      int      `json:"ssh_login_grace_time,omitempty"`       // seconds, 0 = not set
	SSHAllowUsers          []string `json:"ssh_allow_users,omitempty"`            // narrowing: good
	SSHAllowGroups         []string `json:"ssh_allow_groups,omitempty"`           // narrowing: good
	SSHPubkeyAuth          bool     `json:"ssh_pubkey_auth"`                      // should be yes
	SSHX11Forwarding       bool     `json:"ssh_x11_forwarding,omitempty"`         // should be no on servers
	SSHAgentForwarding     bool     `json:"ssh_agent_forwarding,omitempty"`       // should be no on servers
	SSHPermitEmptyPwd      bool     `json:"ssh_permit_empty_passwords,omitempty"` // must be no
	SSHStrictModes         bool     `json:"ssh_strict_modes"`                     // should be yes (default yes)
	SSHClientAliveInterval int      `json:"ssh_client_alive_interval,omitempty"`  // idle timeout seconds
	// Additional CIS/STIG fields
	SSHIgnoreRhosts  bool   `json:"ssh_ignore_rhosts"`             // should be yes (default yes)
	SSHHostbasedAuth bool   `json:"ssh_hostbased_auth,omitempty"`  // should be no
	SSHPermitUserEnv bool   `json:"ssh_permit_user_env,omitempty"` // should be no
	SSHTCPForwarding bool   `json:"ssh_tcp_forwarding,omitempty"`  // should be no on servers
	SSHLogLevel      string `json:"ssh_log_level,omitempty"`       // INFO or VERBOSE
	SSHBanner        string `json:"ssh_banner,omitempty"`          // /etc/issue.net recommended
	SSHMaxSessions   int    `json:"ssh_max_sessions,omitempty"`    // CIS: <= 10
	SSHMaxStartups   string `json:"ssh_max_startups,omitempty"`    // CIS: 10:30:60
	SSHCiphers       string `json:"ssh_ciphers,omitempty"`
	SSHMACs          string `json:"ssh_macs,omitempty"`
	SSHKexAlgorithms string `json:"ssh_kex_algorithms,omitempty"`
	SSHAuditSource   string `json:"ssh_audit_source,omitempty"` // "sshd -T" or "file"

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
	SudoNopasswd          []string `json:"sudo_nopasswd,omitempty"`           // users/groups with NOPASSWD
	SUIDBinaries          []string `json:"suid_binaries,omitempty"`           // unexpected SUID binaries
	UID0Users             []string `json:"uid0_users,omitempty"`              // non-root users with UID 0
	SuspectCrons          []string `json:"suspect_crons,omitempty"`           // cron jobs writing to sensitive paths
	EmptyPasswordAccounts []string `json:"empty_password_accounts,omitempty"` // accounts with empty password field (CRIT)
	StalePasswordAccounts []string `json:"stale_password_accounts,omitempty"` // human UIDs with no password expiry (WARN)
	WorldWritableDirs     []string `json:"world_writable_dirs,omitempty"`     // world-writable dirs missing sticky bit

	// AppArmor (SLES/Ubuntu/Debian)
	AppArmorMode     string           `json:"apparmor_mode,omitempty"`     // enforce, complain, disabled
	AppArmorProfiles int              `json:"apparmor_profiles,omitempty"` // total loaded profiles
	AppArmorComplain int              `json:"apparmor_complain,omitempty"` // profiles in complain mode
	AppArmorDenials  int              `json:"apparmor_denials,omitempty"`  // denials in last hour
	AppArmorGroups   []AppArmorDenial `json:"apparmor_groups,omitempty"`   // grouped AppArmor denials

	// SELinux
	SELinuxDenials     int               `json:"se_linux_denials"` // denials in last hour
	SELinuxMode        string            `json:"se_linux_mode"`
	SELinuxAVCGroups   []SELinuxAVCGroup `json:"se_linux_avc_groups,omitempty"`   // grouped denials
	SELinuxBooleans    []SELinuxBoolean  `json:"se_linux_booleans,omitempty"`     // relevant off booleans
	SELinuxAutoRelabel bool              `json:"se_linux_auto_relabel,omitempty"` // /.autorelabel present
	// PAM
	PAMLockedAccounts []string `json:"pam_locked_accounts,omitempty"` // accounts locked by pam_faillock

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

	// Proxmox VE host flag — suppresses false-positive WARNs for ports and SSH
	// settings that are mandatory on PVE (web UI 8006, spiceproxy 3128,
	// rpcbind 111, and root SSH login required for cluster management).
	IsPVE bool `json:"is_pve,omitempty"`
}

// PortEntry describes a listening network port.
type PortEntry struct {
	Port     int    `json:"port"`
	Protocol string `json:"protocol"`
	Process  string `json:"process"`
	Expected bool   `json:"expected"`
}

// SELinuxAVCGroup is a deduplicated group of AVC denials sharing the same
// source context, target context, and class — the unit an admin acts on.
type SELinuxAVCGroup struct {
	Scontext   string   `json:"scontext"`              // source context (e.g. init_t)
	Tcontext   string   `json:"tcontext"`              // target context (e.g. container_runtime_t)
	Tclass     string   `json:"tclass"`                // object class (e.g. bpf, file, port)
	Perms      []string `json:"perms"`                 // denied permissions (e.g. prog_run, read, write)
	Count      int      `json:"count"`                 // number of denials in window
	BooleanFix string   `json:"boolean_fix,omitempty"` // getsebool name to toggle, if any
	FixCmd     string   `json:"fix_cmd,omitempty"`     // recommended fix command
}

// AppArmorDenial is a grouped AppArmor denial entry.
type AppArmorDenial struct {
	Profile   string `json:"profile"`
	Operation string `json:"operation,omitempty"` // read, write, exec, etc.
	Path      string `json:"path,omitempty"`
	Count     int    `json:"count"`
}

// SELinuxBoolean holds the state of a relevant SELinux boolean.
type SELinuxBoolean struct {
	Name   string `json:"name"`
	Active bool   `json:"active"`  // current value
	SetCmd string `json:"set_cmd"` // exact setsebool command to enable
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
