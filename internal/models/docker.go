package models

// DockerDaemon holds daemon-level health data from /info and /version.
type DockerDaemon struct {
	Responding      bool   `json:"responding"`
	Version         string `json:"version,omitempty"`
	APIVersion      string `json:"api_version,omitempty"`
	StorageDriver   string `json:"storage_driver,omitempty"`
	SwarmState      string `json:"swarm_state,omitempty"`  // inactive, active, pending
	SwarmRole       string `json:"swarm_role,omitempty"`   // manager, worker
	Architecture    string `json:"architecture,omitempty"` // host arch from GET /info (7i)
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
	ImageArch           string   `json:"image_arch,omitempty"`            // 7i: image architecture
	ArchMismatch        bool     `json:"arch_mismatch,omitempty"`         // 7i: image arch != host arch
}

// DockerContainerLogFile holds per-container log file size info.
type DockerContainerLogFile struct {
	Name   string  `json:"name"`
	SizeMB float64 `json:"size_mb"`
}

// DockerLogDriverInfo holds log driver config and per-container log sizes.
type DockerLogDriverInfo struct {
	Driver           string                   `json:"driver"`       // json-file, journald, local, none
	MaxSizeSet       bool                     `json:"max_size_set"` // log-opts.max-size present
	MaxFileSet       bool                     `json:"max_file_set"` // log-opts.max-file present
	DaemonJSONExists bool                     `json:"daemon_json_exists"`
	ContainerLogs    []DockerContainerLogFile `json:"container_logs,omitempty"`
	LargeLogCount    int                      `json:"large_log_count,omitempty"` // >500MB
}

// DockerEvent is a recent system event from the Docker/Podman daemon.
type DockerEvent struct {
	Action   string `json:"action"` // die, oom, kill, start, stop
	Actor    string `json:"actor"`  // container name or ID
	Status   string `json:"status,omitempty"`
	TimeUnix int64  `json:"time"`
}

// PodmanQuadlet holds the state of a systemd-managed Podman container or pod
// defined as a .container/.pod file under /etc/containers/systemd/ (or the
// root user's ~/.config/containers/systemd/). These are not visible via the
// Podman socket — systemd generates a service unit for each quadlet file.
type PodmanQuadlet struct {
	Name        string `json:"name"`
	UnitFile    string `json:"unit_file"`
	ServiceUnit string `json:"service_unit"`
	Active      bool   `json:"active"`
	Failed      bool   `json:"failed"`
	State       string `json:"state"`
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
	PodmanQuadlets   []PodmanQuadlet `json:"podman_quadlets,omitempty"`
	DiskUsageGB      float64         `json:"disk_usage_gb"`
	ImagesCount      int             `json:"images_count"`
	DanglingImages   int             `json:"dangling_images"`
	DanglingImagesMB float64         `json:"dangling_images_mb"`
	VolumesCount     int             `json:"volumes_count"`
	OrphanedVolumes  int             `json:"orphaned_volumes"`
	// Network health
	NetworkBackend    string `json:"network_backend,omitempty"` // "netavark", "cni", "iptables"
	MTUMismatch       bool   `json:"mtu_mismatch"`
	HostMTU           int    `json:"host_mtu,omitempty"`
	ContainerMTU      int    `json:"container_mtu,omitempty"`
	IPForwardEnabled  bool   `json:"ip_forward_enabled"` // /proc/sys/net/ipv4/ip_forward
	FirewalldActive   bool   `json:"firewalld_active,omitempty"`
	FirewalldBackend  string `json:"firewalld_backend,omitempty"` // "nftables" or "iptables"
	DockerZoneTrusted bool   `json:"docker_zone_trusted,omitempty"`
	// Security
	ContainersWithSecrets int `json:"containers_with_secrets,omitempty"` // count with plaintext env secrets
	RunningAsRootCount    int `json:"running_as_root_count,omitempty"`   // running containers with root user
	SocketMountedCount    int `json:"socket_mounted_count,omitempty"`    // containers with docker.sock mounted
	// Recent events (die, oom, kill in last 1h)
	RecentEvents []DockerEvent `json:"recent_events,omitempty"`
	OOMEvents    int           `json:"oom_events,omitempty"`
	// Deep only — log driver + container log sizes (Docker only)
	LogDriver *DockerLogDriverInfo `json:"log_driver,omitempty"`
	// 7g: DNS trap — host resolv.conf uses loopback address
	DNSTrap             bool     `json:"dns_trap,omitempty"`
	DNSTrapServer       string   `json:"dns_trap_server,omitempty"`
	DaemonDNSServers    []string `json:"daemon_dns_servers,omitempty"`
	DaemonDNSConfigured bool     `json:"daemon_dns_configured,omitempty"`
	// 7h: socket permission diagnosis
	SocketPermDenied bool `json:"socket_perm_denied,omitempty"`
	// 7i: image architecture mismatch
	HostArch          string `json:"host_arch,omitempty"`
	ArchMismatchCount int    `json:"arch_mismatch_count,omitempty"`
	Status            string `json:"status,omitempty"`
	StatusReason      string `json:"status_reason,omitempty"`
}
