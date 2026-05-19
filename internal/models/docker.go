package models

// ContainerInfo holds health data for a single Docker/Podman container.
type ContainerInfo struct {
	ID      string `json:"id"`
	Name    string `json:"name"`
	Image   string `json:"image"`
	State   string `json:"state"`  // running, exited, paused, dead, etc.
	Health  string `json:"health"` // healthy, unhealthy, starting, none
	Restart int    `json:"restart"`
}

// DockerInfo holds Docker/Podman daemon health data.
type DockerInfo struct {
	Available        bool            `json:"available"` // Docker/Podman daemon reachable
	Runtime          string          `json:"runtime"`   // "docker" or "podman"
	TotalContainers  int             `json:"total_containers"`
	RunningCount     int             `json:"running_count"`
	StoppedCount     int             `json:"stopped_count"`
	Stopped          int             `json:"stopped"` // alias for heuristics
	UnhealthyCount   int             `json:"unhealthy_count"`
	Unhealthy        []string        `json:"unhealthy,omitempty"` // names of unhealthy containers
	CrashLoopCount   int             `json:"crash_loop_count"`
	CrashLooping     []string        `json:"crash_looping,omitempty"` // names of crash-looping containers
	Containers       []ContainerInfo `json:"containers,omitempty"`
	DiskUsageGB      float64         `json:"disk_usage_gb"`
	ImagesCount      int             `json:"images_count"`
	DanglingImages   int             `json:"dangling_images"`
	DanglingImagesMB float64         `json:"dangling_images_mb"`
	VolumesCount     int             `json:"volumes_count"`
	OrphanedVolumes  int             `json:"orphaned_volumes"`
	// Network health
	NetworkBackend string `json:"network_backend,omitempty"` // "netavark" (nftables), "cni" (iptables), "unknown"
	MTUMismatch    bool   `json:"mtu_mismatch"`              // container network MTU ≠ host interface MTU
	HostMTU        int    `json:"host_mtu,omitempty"`
	ContainerMTU   int    `json:"container_mtu,omitempty"`
	Status         string `json:"status,omitempty"`
	StatusReason   string `json:"status_reason,omitempty"`
}
