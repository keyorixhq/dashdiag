package models

type SlowUnit struct {
	Name     string  `json:"name"`
	Duration float64 `json:"duration_sec"` // seconds from systemd-analyze blame
}

type SystemdInfo struct {
	Available        bool       `json:"available"`
	FailedUnits      []string   `json:"failed_units"`
	StuckUnits       []string   `json:"stuck_units"`
	SlowUnits        []SlowUnit `json:"slow_units,omitempty"`        // top 3 slow boot units
	TotalBootSec     float64    `json:"total_boot_sec,omitempty"`    // total boot time in seconds
	SELinuxEnforcing bool       `json:"selinux_enforcing,omitempty"` // cross-check: SELinux enforcing when units fail
	Status           string     `json:"status"`
	StatusReason     string     `json:"status_reason"`
}
