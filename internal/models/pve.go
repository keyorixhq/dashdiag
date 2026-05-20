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

// PVEGuest represents a VM or LXC container.
type PVEGuest struct {
	VMID     int     `json:"vmid"`
	Name     string  `json:"name"`
	Type     string  `json:"type"`   // "qemu" or "lxc"
	Status   string  `json:"status"` // "running", "stopped", "paused"
	OnBoot   bool    `json:"onboot"`
	CPUs     int     `json:"cpus,omitempty"`
	MaxMemGB float64 `json:"max_mem_gb,omitempty"`
}

// PVETaskError represents a recent failed task.
type PVETaskError struct {
	Type    string `json:"type"` // "vzdump", "qmigrate", "vzsnapshot"...
	VMID    string `json:"vmid,omitempty"`
	StartAt string `json:"start_at,omitempty"` // HH:MM
	Msg     string `json:"msg,omitempty"`
}

// PVEPerf holds pveperf benchmark results.
type PVEPerf struct {
	Available      bool    `json:"available"` // pveperf binary found
	Path           string  `json:"path"`      // tested path
	CPUBogomips    float64 `json:"cpu_bogomips,omitempty"`
	RegexPerSec    float64 `json:"regex_per_sec,omitempty"`
	BufferedReadMB float64 `json:"buffered_read_mb,omitempty"`
	AvgSeekMs      float64 `json:"avg_seek_ms,omitempty"`
	FsyncsPerSec   float64 `json:"fsyncs_per_sec,omitempty"`
	DNSExtMs       float64 `json:"dns_ext_ms,omitempty"`
	DNSIntMs       float64 `json:"dns_int_ms,omitempty"`
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

	// Guests
	Guests       []PVEGuest `json:"guests,omitempty"`
	RunningCount int        `json:"running_count"`
	StoppedCount int        `json:"stopped_count"`
	PausedCount  int        `json:"paused_count"`

	// Resource overcommit
	TotalVCPUs    int     `json:"total_vcpus"`
	PhysicalCores int     `json:"physical_cores"`
	TotalMemGB    float64 `json:"total_mem_gb"` // sum of maxmem for running guests
	HostMemGB     float64 `json:"host_mem_gb"`  // physical RAM

	// Task errors (last 24h)
	TaskErrors []PVETaskError `json:"task_errors,omitempty"`

	// Performance (deep only)
	Perf *PVEPerf `json:"perf,omitempty"`

	// Meta
	IsPVE     bool `json:"is_pve"`     // false = not a Proxmox host
	NeedsRoot bool `json:"needs_root"` // some checks require root
}
