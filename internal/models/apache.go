package models

// ApacheInfo holds guest-side health for a local Apache httpd server. Gated on a
// running httpd/apache2 process. Like nginx, the headline is config validity:
// the server keeps serving its last-loaded config, so a broken on-disk config is
// invisible until the next reload — `apachectl configtest` surfaces it first.
type ApacheInfo struct {
	Detected     bool   `json:"detected"`
	Version      string `json:"version,omitempty"`
	ConfigTested bool   `json:"config_tested"`
	ConfigValid  bool   `json:"config_valid,omitempty"`
	ConfigError  string `json:"config_error,omitempty"`
	StatusReason string `json:"status_reason,omitempty"`
}
