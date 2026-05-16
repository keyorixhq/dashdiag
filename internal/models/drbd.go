package models

// DRBDResource represents a single DRBD resource from /proc/drbd.
type DRBDResource struct {
	Minor      int     `json:"minor"`                  // resource minor number (0, 1, 2...)
	ConnState  string  `json:"conn_state"`             // cs: Connected, StandAlone, SplitBrain, WFConnection...
	LocalRole  string  `json:"local_role"`             // ro: Primary or Secondary
	LocalDisk  string  `json:"local_disk"`             // ds (local): UpToDate, Inconsistent, Outdated, Failed...
	RemoteDisk string  `json:"remote_disk"`            // ds (remote): UpToDate, Inconsistent, Outdated...
	SyncPct    float64 `json:"sync_pct,omitempty"`     // sync progress % (populated during SyncSource/SyncTarget)
	SyncKBLeft int64   `json:"sync_kb_left,omitempty"` // KB remaining to sync
}

// DRBDInfo holds health data for all DRBD resources on the system.
type DRBDInfo struct {
	Version   string         `json:"version,omitempty"`
	Resources []DRBDResource `json:"resources,omitempty"`
}
