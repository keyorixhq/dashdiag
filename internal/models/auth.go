package models

// FailedLoginSource is one IP/host with repeated failed logins.
type FailedLoginSource struct {
	Source string `json:"source"` // IP address or hostname
	Count  int    `json:"count"`
}

// AuthInfo holds authentication failure data from auth.log / journald.
type AuthInfo struct {
	Available     bool                `json:"available"` // false when sshd is not running — row is hidden
	Checked       bool                `json:"checked"`   // true when auth log was readable
	FailedLast24h int                 `json:"failed_last_24h"`
	TopSources    []FailedLoginSource `json:"top_sources,omitempty"` // top 5 by count
	RootAttempts  int                 `json:"root_attempts,omitempty"`
	Status        string              `json:"status,omitempty"`
	StatusReason  string              `json:"status_reason,omitempty"`

	// Effective sshd auth policy, populated only from the authoritative `sshd -T`
	// read (never the ambiguous file-parse fallback). Lets the brute-force verdict
	// be config-aware: failed password attempts against a key-only host cannot
	// succeed, so they are noise (INFO), not a "brute force likely" WARN. When
	// SSHConfigChecked is false the policy is unknown — fail toward warning.
	SSHConfigChecked         bool `json:"ssh_config_checked,omitempty"`          // true only when `sshd -T` was readable
	PasswordAuthEnabled      bool `json:"password_auth_enabled,omitempty"`       // PasswordAuthentication yes
	RootPasswordLoginAllowed bool `json:"root_password_login_allowed,omitempty"` // PermitRootLogin yes (password root login possible)
}
