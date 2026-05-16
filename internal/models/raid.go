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
}
