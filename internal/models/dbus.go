package models

// DBusInfo reports the health of the D-Bus system message bus.
// D-Bus is a Tier-0 dependency: when it fails, all services that use
// inter-process communication cascade-fail (NetworkManager, systemd-logind,
// and many others). It is checked before the main collector goroutines run.
type DBusInfo struct {
	// Available is false on platforms where D-Bus is not present (macOS).
	Available bool `json:"available"`
	// Active is true when dbus.service is running.
	Active bool `json:"active"`
	// Status is the raw systemctl is-active output: "active", "failed", "inactive".
	Status string `json:"status"`
	// LastError is the most recent error line from the D-Bus journal, if failed.
	LastError string `json:"last_error,omitempty"`
}
