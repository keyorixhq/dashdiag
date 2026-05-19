package models

// DockerDaemon holds daemon-level health data from /info and /version.
type DockerDaemon struct {
	Responding      bool   `json:"responding"`
	Version         string `json:"version,omitempty"`
	APIVersion      string `json:"api_version,omitempty"`
	StorageDriver   string `json:"storage_driver,omitempty"`
	SwarmState      string `json:"swarm_state,omitempty"` // inactive, active, pending
	RecentErrors    int    `json:"recent_errors,omitempty"`
	LastDaemonError string `json:"last_daemon_error,omitempty"`
}

// ContainerInfo holds health data for a single Docker/Podman container.
type ContainerInfo struct {
	ID                  string   `json:"id"`
	Name                string   `json:"name"`
	Image               string   `json:"image"`
	State               string   `json:"state"`  // running, exited, paused, dead, etc.
	Health              string   `json:"health"` // healthy, unhealthy, starting, none
	Restart             int      `json:"restart"`
	ExitCode            int      `json:"exit_code,omitempty"`
	ExitLabel           string   `json:"exit_label,omitempty"`        // "OOM kill", "segfault", etc.
	PlaintextSecrets    []string `json:"plaintext_secrets,omitempty"` // env var names only
	RunsAsRoot          bool     `json:"runs_as_root,omitempty"`      // Config.User == "" or "0" or "root"
	User                string   `json:"user,omitempty"`
	DockerSocketMounted bool     `json:"docker_socket_mounted,omitempty"` // docker.sock in HostConfig.Binds
}

// DockerEvent is a recent system event from the Docker/Podman daemon.
type DockerEvent struct {
	Action   string `json:"action"` // die, oom, kill, start, stop
	Actor    string `json:"actor"`  // container name or ID
	Status   string `json:"status,omitempty"`
	TimeUnix int64  `json:"time"`
}

// DockerInfo holds Docker/Podman daemon health data.
type DockerInfo struct {
	Available        bool            `json:"available"` // Docker/Podman daemon reachable
	Runtime          string          `json:"runtime"`   // "docker" or "podman"
	Daemon           *DockerDaemon   `json:"daemon,omitempty"`
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
	// Security
	ContainersWithSecrets int `json:"containers_with_secrets,omitempty"` // count with plaintext env secrets
	RunningAsRootCount    int `json:"running_as_root_count,omitempty"`   // running containers with root user
	SocketMountedCount    int `json:"socket_mounted_count,omitempty"`    // containers with docker.sock mounted
	// Recent events (die, oom, kill in last 1h)
	RecentEvents []DockerEvent `json:"recent_events,omitempty"`
	OOMEvents    int           `json:"oom_events,omitempty"`
	Status       string        `json:"status,omitempty"`
	StatusReason string        `json:"status_reason,omitempty"`
}
