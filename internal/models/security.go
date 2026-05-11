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

	// Privilege escalation
	SudoNopasswd []string `json:"sudo_nopasswd,omitempty"` // users/groups with NOPASSWD
	SUIDBinaries []string `json:"suid_binaries,omitempty"` // unexpected SUID binaries

	// SELinux
	SELinuxDenials int    `json:"se_linux_denials"` // denials in last hour
	SELinuxMode    string `json:"se_linux_mode"`

	Status       string `json:"status,omitempty"`
	StatusReason string `json:"status_reason,omitempty"`
	NeedsRoot    bool   `json:"needs_root,omitempty"` // some checks require root
}

// PortEntry describes a listening network port.
type PortEntry struct {
	Port     int    `json:"port"`
	Protocol string `json:"protocol"`
	Process  string `json:"process"`
	Expected bool   `json:"expected"`
}
