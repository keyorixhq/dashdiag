package models

// PVESubscription holds Proxmox VE subscription status.
type PVESubscription struct {
	Status  string `json:"status"`  // "active", "expired", "notfound", "unknown"
	Level   string `json:"level"`   // "c", "b", "a", "p" (community→premium)
	Product string `json:"product"` // e.g. "Proxmox VE Standard Subscription"
}

// PVEStorage represents a single Proxmox storage backend.
type PVEStorage struct {
	Name    string  `json:"name"` // e.g. "local", "local-lvm", "ceph"
	Type    string  `json:"type"` // "dir", "lvm", "zfspool", "rbd", "nfs"
	UsedPct float64 `json:"used_pct"`
	UsedGB  float64 `json:"used_gb"`
	TotalGB float64 `json:"total_gb"`
	Active  bool    `json:"active"`
}

// PVEBackupTask represents a recent backup task result.
type PVEBackupTask struct {
	VMID    int    `json:"vmid"`
	Status  string `json:"status"`   // "OK", "WARNING", "ERROR"
	EndTime int64  `json:"end_time"` // unix timestamp
}

// PVENode represents a node in the Proxmox cluster.
type PVENode struct {
	Name    string `json:"name"`
	Online  bool   `json:"online"`
	Version string `json:"version"` // PVE version string
}

// PVEInfo holds all Proxmox VE health data.
type PVEInfo struct {
	// Cluster
	ClusterName  string    `json:"cluster_name,omitempty"`
	QuorumOK     bool      `json:"quorum_ok"`
	Nodes        []PVENode `json:"nodes,omitempty"`
	HAFencingOK  bool      `json:"ha_fencing_ok"`
	HAFencingMsg string    `json:"ha_fencing_msg,omitempty"`

	// This node
	Subscription  PVESubscription `json:"subscription"`
	Storages      []PVEStorage    `json:"storages,omitempty"`
	RecentBackups []PVEBackupTask `json:"recent_backups,omitempty"`
	BackupAgeDays int             `json:"backup_age_days"` // days since last successful backup (-1 = never)

	// Meta
	IsPVE     bool `json:"is_pve"`     // false = not a Proxmox host
	NeedsRoot bool `json:"needs_root"` // some checks require root
}
