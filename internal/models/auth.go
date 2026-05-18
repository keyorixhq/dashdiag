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
}
