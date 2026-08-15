package models

// ISCSISession is one active iSCSI session.
type ISCSISession struct {
	Target string `json:"target"`
	Portal string `json:"portal"`
	State  string `json:"state"`            // LOGGED_IN, FAILED
	Device string `json:"device,omitempty"` // /dev/sdX
}

// ISCSIInfo holds iSCSI initiator session health.
type ISCSIInfo struct {
	Available bool           `json:"available"`
	Sessions  []ISCSISession `json:"sessions,omitempty"`
	// NeedsRoot is true when active sessions exist in sysfs but `iscsiadm -m session
	// -P 1` could not read their state unprivileged (the per-session sysfs fields it
	// reads, e.g. username, are mode 0400). The session state is unknown, NOT healthy:
	// the verdict must say "needs root", not silently omit a possibly-failed session.
	NeedsRoot bool `json:"needs_root,omitempty"`
	// SessionsParseFailed is true when `iscsiadm -m session -P 1` exited 0 but
	// no recognizable session data was parsed from its output, while
	// /sys/class/iscsi_session/ (world-readable) shows session directories
	// actually exist — a format/locale mismatch, not "genuinely no sessions".
	SessionsParseFailed bool   `json:"sessions_parse_failed,omitempty"`
	FailedCount         int    `json:"failed_count,omitempty"`
	Status              string `json:"status,omitempty"`
	StatusReason        string `json:"status_reason,omitempty"`
}
