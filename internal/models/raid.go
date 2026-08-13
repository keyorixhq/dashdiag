package models

// RAIDDevice represents a single mdadm RAID array from /proc/mdstat.
type RAIDDevice struct {
	Name       string   `json:"name"`                  // e.g. "md0"
	Level      string   `json:"level"`                 // e.g. "raid1", "raid5"
	State      string   `json:"state"`                 // "active", "degraded", "recovering", "failed"
	Active     int      `json:"active"`                // number of active drives
	Total      int      `json:"total"`                 // expected number of drives
	Failed     []string `json:"failed"`                // failed drive names
	Spare      []string `json:"spare"`                 // spare drive names
	RebuildPct float64  `json:"rebuild_pct,omitempty"` // recovery progress %
}

// RAIDInfo holds all mdadm RAID array status from /proc/mdstat.
type RAIDInfo struct {
	Arrays []RAIDDevice `json:"arrays,omitempty"`
	// ReadFailed is true when /proc/mdstat exists but could not be read (a
	// non-ENOENT error — permission, hardened LSM policy, procfs oddities).
	// /proc/mdstat is a kernel-provided virtual file present on effectively
	// every Linux host regardless of whether mdadm arrays are configured, so
	// a genuine open failure here is NOT the same as "no RAID configured" —
	// without this flag, both collapse to an empty Arrays slice and read as
	// an identical clean "no RAID" result.
	ReadFailed bool `json:"read_failed,omitempty"`
}
