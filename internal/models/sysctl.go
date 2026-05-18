package models

type SysctlInfo struct {
	Available bool `json:"available"` // false on non-Linux
	// Core
	VMSwappiness int `json:"vm_swappiness"`
	NetSomaxconn int `json:"net_somaxconn"`
	FSFileMax    int `json:"fs_file_max"`
	KernelPIDMax int `json:"kernel_pid_max"`
	PIDCount     int `json:"pid_count"`

	// Network tuning
	NetRmemMax    int `json:"net_rmem_max"`    // net.core.rmem_max
	NetWmemMax    int `json:"net_wmem_max"`    // net.core.wmem_max
	TCPTWReuse    int `json:"tcp_tw_reuse"`    // net.ipv4.tcp_tw_reuse
	TCPSynBacklog int `json:"tcp_syn_backlog"` // net.ipv4.tcp_max_syn_backlog

	// VM tuning
	VMMaxMapCount          int `json:"vm_max_map_count"`          // vm.max_map_count
	VMDirtyRatio           int `json:"vm_dirty_ratio"`            // vm.dirty_ratio
	VMDirtyBackgroundRatio int `json:"vm_dirty_background_ratio"` // vm.dirty_background_ratio
	VMOvercommit           int `json:"vm_overcommit"`             // vm.overcommit_memory

	// Filesystem
	FSInotifyWatches int `json:"fs_inotify_watches"` // fs.inotify.max_user_watches

	// Detected workload
	Workload string `json:"workload,omitempty"` // k8s, webserver, database, default

	Status       string `json:"status"`
	StatusReason string `json:"status_reason"`
}
