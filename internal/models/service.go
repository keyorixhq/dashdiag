package models

type ServiceResult struct {
	Name       string  `json:"name"`
	Host       string  `json:"host"`
	Port       int     `json:"port"`
	Protocol   string  `json:"protocol"`
	Reachable  bool    `json:"reachable"`
	LatencyMs  float64 `json:"latency_ms"`
	StatusCode int     `json:"status_code,omitempty"`
	Error      string  `json:"error,omitempty"`
	Status     string  `json:"status"`
}

type ServicesInfo struct {
	Results []ServiceResult `json:"results"`
	Status  string          `json:"status"`
}

// SystemdUnit holds the health of a single failed systemd unit.
type SystemdUnit struct {
	Name           string   `json:"name"`
	ExitCode       int      `json:"exit_code"`
	ActiveState    string   `json:"active_state"`
	SubState       string   `json:"sub_state"`
	LastLogLines   []string `json:"last_log_lines,omitempty"`
	SELinuxDenials []string `json:"selinux_denials,omitempty"`
}

// BootOffender is a service with a notably long startup time.
type BootOffender struct {
	Unit       string `json:"unit"`
	DurationMs int    `json:"duration_ms"`
}

// UserUnitsInfo holds systemd --user unit health for the current user session.
type UserUnitsInfo struct {
	Available bool          `json:"available"` // false = no user daemon running
	Failed    []SystemdUnit `json:"failed,omitempty"`
}

// ServicesDeepInfo is the output of `dsd services deep`.
// It combines port connectivity results (same as ServicesInfo) with a full
// systemd health layer: failed units, boot offenders, journal integrity,
// masked units, and daemon-reload status.
type ServicesDeepInfo struct {
	// Port health — same checks as dsd services fast.
	PortResults []ServiceResult `json:"port_results,omitempty"`

	// Systemd health
	FailedUnits       []SystemdUnit  `json:"failed_units,omitempty"`
	NeedsDaemonReload []string       `json:"needs_daemon_reload,omitempty"`
	MaskedUnits       []string       `json:"masked_units,omitempty"`
	JournalHealthy    bool           `json:"journal_healthy"`
	JournalLastValid  string         `json:"journal_last_valid,omitempty"`
	BootOffenders     []BootOffender `json:"boot_top_offenders,omitempty"`
	UserUnits         *UserUnitsInfo `json:"user_units,omitempty"`
}
