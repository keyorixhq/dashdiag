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
	// CtrBinaryFound is true only when a usable ctr/containerd-ctr binary was
	// located and used to enumerate Namespaces/TotalContainers. False means
	// namespace/container enumeration was never attempted (binary removed,
	// renamed, blocked via PATH) — Namespaces stays nil and TotalContainers
	// stays 0 exactly as they would for a genuinely idle containerd with zero
	// namespaces. Callers must not treat that zero-value pair as "verified
	// clean" when this is false.
	CtrBinaryFound bool `json:"ctr_binary_found,omitempty"`
	// NamespacesTruncated is true when `ctr namespaces list` reported more
	// namespaces than the collector will fan a per-namespace `ctr containers
	// list` subprocess out to (maxContainerdNamespaces in
	// containerd_linux.go). internal-collectors-05-04: enumerating every
	// reported namespace with no cap let a namespace-bombing scenario spawn an
	// unbounded number of subprocesses. Namespaces/TotalContainers still cover
	// the first maxContainerdNamespaces (sorted) when this is true — this flag
	// says the count is a floor, not the full picture, so a caller must not
	// treat it as "verified — this is every namespace on the host".
	NamespacesTruncated bool `json:"namespaces_truncated,omitempty"`
}

// ContainerdNamespace holds container counts for one containerd namespace.
// containerd uses namespaces to isolate container sets (k8s.io, moby, default).
type ContainerdNamespace struct {
	Name           string `json:"name"`
	ContainerCount int    `json:"container_count"`
}
