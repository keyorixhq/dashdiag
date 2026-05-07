package models

type PortEntry struct {
	Port     int    `json:"port"`
	Protocol string `json:"protocol"`
	Process  string `json:"process"`
	Expected bool   `json:"expected"`
}

type SecurityInfo struct {
	FailedLogins     int         `json:"failed_logins"`
	ListeningPorts   []PortEntry `json:"listening_ports"`
	SSHPermitRoot    bool        `json:"ssh_permit_root"`
	SSHPasswordAuth  bool        `json:"ssh_password_auth"`
	SudoNopasswd     []string    `json:"sudo_nopasswd"`
	WorldWritableEtc []string    `json:"world_writable_etc"`
	Status           string      `json:"status"`
	StatusReason     string      `json:"status_reason"`
}
