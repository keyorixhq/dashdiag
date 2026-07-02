package models

// ContainerdInfo holds health data for a standalone containerd runtime.
// Only collected when containerd is running without a Kubernetes layer
// (k3s/Rancher standalone). When kubelet is present, dsd k8s already
// covers containerd via its OS-layer checks — no double-counting.
type ContainerdInfo struct {
	Available       bool                  `json:"available"`         // socket connectable
	ServiceState    string                `json:"service_state"`     // active, inactive, failed, unknown
	Version         string                `json:"version,omitempty"` // containerd version string
	SocketPath      string                `json:"socket_path"`       // detected socket path
	Namespaces      []ContainerdNamespace `json:"namespaces,omitempty"`
	TotalContainers int                   `json:"total_containers"`
	// Status fields for unavailable/error cases
	Status       string `json:"status,omitempty"`
	StatusReason string `json:"status_reason,omitempty"`
	// SocketPermDenied is true when the socket exists but dialing it was
	// refused (EACCES) — containerd IS installed and likely running, dsd just
	// lacks permission. Distinct from a genuinely absent socket (mirrors
	// DockerInfo.SocketPermDenied): without it, "socket exists but denied" and
	// "socket doesn't exist at all" collapsed into the same message, and
	// non-root `dsd containerd` printed "not installed or not running" for a
	// runtime that was actually right there.
	SocketPermDenied bool `json:"socket_perm_denied,omitempty"`
}

// ContainerdNamespace holds container counts for one containerd namespace.
// containerd uses namespaces to isolate container sets (k8s.io, moby, default).
type ContainerdNamespace struct {
	Name           string `json:"name"`
	ContainerCount int    `json:"container_count"`
}
