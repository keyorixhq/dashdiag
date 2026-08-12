package models

type SlowUnit struct {
	Name     string  `json:"name"`
	Duration float64 `json:"duration_sec"` // seconds from systemd-analyze blame
}

type SystemdInfo struct {
	Available          bool     `json:"available"`
	FailedUnits        []string `json:"failed_units"`
	FailedUnitsUnknown bool     `json:"failed_units_unknown,omitempty"` // systemctl list-units --failed did not run (timeout/error) — failed state unverified
	// SSHDStatusUnverified is true when at least one blanket-suppressed sshd@
	// per-connection instance's ExecMainStatus lookup failed (timeout/error). That
	// instance is left out of FailedUnits (fail-safe, to avoid re-flooding on a
	// benign scan pile), but a genuine per-connection sshd fault could be the one
	// whose status couldn't be read — never let that read as a clean "no non-benign
	// sshd@ failures" verdict.
	SSHDStatusUnverified bool       `json:"sshd_status_unverified,omitempty"`
	NeedsDaemonReload    []string   `json:"needs_daemon_reload,omitempty"` // unit files changed on disk, not yet reloaded
	StuckUnits           []string   `json:"stuck_units"`
	SlowUnits            []SlowUnit `json:"slow_units,omitempty"`        // top 3 slow boot units
	TotalBootSec         float64    `json:"total_boot_sec,omitempty"`    // total boot time in seconds
	SystemState          string     `json:"system_state,omitempty"`      // `systemctl is-system-running`: running/degraded/maintenance/… ("maintenance" = booted into emergency/rescue)
	SELinuxEnforcing     bool       `json:"selinux_enforcing,omitempty"` // cross-check: SELinux enforcing when units fail
	ZFSPoolsPresent      bool       `json:"zfs_pools_present,omitempty"` // cross-check: host imports ZFS pools — gates zfs-import-*.service failure severity (§O.2)
	Status               string     `json:"status"`
	StatusReason         string     `json:"status_reason"`
}
