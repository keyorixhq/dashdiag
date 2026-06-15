package models

// HAProxyInfo holds guest-side health for a local HAProxy load balancer. Gated on
// a running haproxy process. The headline is config validity (`haproxy -c`): a
// broken on-disk config is a latent outage that only surfaces on the next reload.
type HAProxyInfo struct {
	Detected     bool   `json:"detected"`
	Version      string `json:"version,omitempty"`
	ConfigTested bool   `json:"config_tested"`
	ConfigValid  bool   `json:"config_valid,omitempty"`
	ConfigError  string `json:"config_error,omitempty"`
	StatusReason string `json:"status_reason,omitempty"`
}
