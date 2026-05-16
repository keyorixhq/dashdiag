package models

// DRBDResource represents a single DRBD replicated block device from /proc/drbd.
// DRBD is used in Pacemaker/Corosync HA clusters for storage replication.
type DRBDResource struct {
	Minor      int     `json:"minor"`       // device minor number (0, 1, 2...)
	ConnState  string  `json:"conn_state"`  // Connected, StandAlone, WFConnection, SplitBrain, etc.
	LocalRole  string  `json:"local_role"`  // Primary, Secondary
	RemoteRole string  `json:"remote_role"` // Primary, Secondary, Unknown
	LocalDisk  string  `json:"local_disk"`  // UpToDate, Inconsistent, Outdated, Failed, etc.
	RemoteDisk string  `json:"remote_disk"` // UpToDate, Inconsistent, Outdated, Unknown, etc.
	SyncPct    float64 `json:"sync_pct"`    // sync progress % (0 when not syncing)
	Syncing    bool    `json:"syncing"`
	OutOfSync  int64   `json:"out_of_sync_kb"` // kilobytes out of sync
}

// DRBDInfo holds health data for all DRBD resources on the system.
type DRBDInfo struct {
	Version   string         `json:"version,omitempty"`
	Resources []DRBDResource `json:"resources,omitempty"`
}
