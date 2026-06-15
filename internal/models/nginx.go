package models

// NginxInfo holds guest-side health for a local nginx server. Gated on a running
// nginx process (silent otherwise). The headline signal is config validity: nginx
// keeps serving its last-loaded config even after the on-disk config is edited, so
// a broken on-disk config is invisible until the next reload/restart kills the
// site — `nginx -t` surfaces it first. Degrades gracefully: ConfigTested is false
// when `nginx -t` couldn't run (e.g. config not readable without root).
type NginxInfo struct {
	Detected      bool   `json:"detected"`
	Version       string `json:"version,omitempty"`
	MasterRunning bool   `json:"master_running"`
	Workers       int    `json:"workers,omitempty"`

	ConfigTested bool   `json:"config_tested"`
	ConfigValid  bool   `json:"config_valid,omitempty"`
	ConfigError  string `json:"config_error,omitempty"` // first error line from nginx -t

	StatusReason string `json:"status_reason,omitempty"`
}
