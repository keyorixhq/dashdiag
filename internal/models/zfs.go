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
}

// ZFSInfo holds health data for all ZFS pools on the system.
type ZFSInfo struct {
	Pools []ZFSPool `json:"pools,omitempty"`
}
