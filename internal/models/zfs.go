package models

// ZFSPool represents a single ZFS pool from zpool status/list output.
type ZFSPool struct {
	Name         string  `json:"name"`
	State        string  `json:"state"`    // ONLINE, DEGRADED, FAULTED, REMOVED, UNAVAIL, OFFLINE
	UsedPct      float64 `json:"used_pct"` // capacity used %
	SizeGB       float64 `json:"size_gb"`
	FreeGB       float64 `json:"free_gb"`
	FragPct      int     `json:"frag_pct"` // fragmentation %
	ReadErrors   int     `json:"read_errors"`
	WriteErrors  int     `json:"write_errors"`
	CksumErrors  int     `json:"cksum_errors"`
	ScrubAgeDays int     `json:"scrub_age_days"`       // days since last scrub (-1 = never scrubbed)
	ScrubErrors  int     `json:"scrub_errors"`         // errors found in last scrub
	StatusMsg    string  `json:"status_msg,omitempty"` // human-readable from zpool status
	// StatusReadFailed is true only when `zpool status <pool>` errored (it can hang
	// on a sick pool and hit the timeout). The pool State above still comes from the
	// primary `zpool list -o …,health`, but the per-vdev error counts and scrub age
	// come from `zpool status` — when that failed they're left at 0 / -1, which
	// would otherwise read as "no errors" + "never scrubbed". Inverted (failure, not
	// success) so the zero value means "read OK".
	StatusReadFailed bool `json:"status_read_failed,omitempty"`
}

// ZFSInfo holds health data for all ZFS pools on the system.
type ZFSInfo struct {
	Pools []ZFSPool `json:"pools,omitempty"`
	// ListReadFailed is true when `zpool` is installed but `zpool list` errored
	// (commonly permission denied — zpool often needs root). Pools is then empty,
	// which would otherwise read as a silent "no ZFS problems"; this lets the verdict
	// say "present but not verified" instead.
	ListReadFailed bool `json:"list_read_failed,omitempty"`
}
