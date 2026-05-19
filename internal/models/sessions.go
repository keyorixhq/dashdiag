package models

// Session is one logged-in user session from `w -h` output.
type Session struct {
	User    string `json:"user"`
	TTY     string `json:"tty"`
	From    string `json:"from,omitempty"` // remote IP or "-" for local
	LoginAt string `json:"login_at"`
	Idle    string `json:"idle"`     // human string: "0.00s", "3:12", "2days"
	IdleSec int    `json:"idle_sec"` // parsed idle seconds for threshold checks
	Command string `json:"command,omitempty"`
}

// SessionsInfo is the output of the SessionsCollector.
type SessionsInfo struct {
	Sessions    []Session `json:"sessions"`
	TotalCount  int       `json:"total_count"`
	RemoteCount int       `json:"remote_count"`
	UniqueIPs   []string  `json:"unique_ips,omitempty"`
	RootSSH     bool      `json:"root_ssh"`            // root logged in via SSH
	LongIdle    []string  `json:"long_idle,omitempty"` // users idle > 8 hours
}
