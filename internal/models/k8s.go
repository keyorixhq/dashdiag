package models

// K8sNodeInfo holds status for a single k8s node.
type K8sNodeInfo struct {
	Name       string            `json:"name"`
	Status     string            `json:"status"` // Ready, NotReady, Unknown
	Roles      string            `json:"roles"`
	Age        string            `json:"age"`
	Version    string            `json:"version"`
	Conditions map[string]string `json:"conditions,omitempty"` // MemoryPressure, DiskPressure etc
}

// K8sPodInfo holds status for a single pod.
type K8sPodInfo struct {
	Namespace      string `json:"namespace"`
	Name           string `json:"name"`
	Ready          string `json:"ready"`  // e.g. "1/1"
	Status         string `json:"status"` // Running, CrashLoopBackOff, Pending etc
	Restarts       int    `json:"restarts"`
	Age            string `json:"age"`
	Image          string `json:"image,omitempty"`           // for ImagePullBackOff
	TerminationMsg string `json:"termination_msg,omitempty"` // lastState.terminated.message
	PreviousLogs   string `json:"previous_logs,omitempty"`   // last 10 lines, CrashLoop only
	Terminating    bool   `json:"terminating,omitempty"`     // deletionTimestamp set
	InitError      string `json:"init_error,omitempty"`      // Init:Error or Init:CrashLoopBackOff
}

// K8sEvent is a Warning event from the cluster.
type K8sEvent struct {
	Namespace string `json:"namespace"`
	Name      string `json:"name"`
	Reason    string `json:"reason"` // OOMKilling, FailedScheduling, BackOff etc
	Message   string `json:"message"`
	Age       string `json:"age"`
}

// K8sPVCInfo holds PVC status.
type K8sPVCInfo struct {
	Namespace string `json:"namespace"`
	Name      string `json:"name"`
	Status    string `json:"status"` // Bound, Pending, Lost
	Capacity  string `json:"capacity,omitempty"`
}

// K8sWorkloadInfo holds Deployment/StatefulSet readiness.
type K8sWorkloadInfo struct {
	Namespace string `json:"namespace"`
	Name      string `json:"name"`
	Kind      string `json:"kind"` // Deployment, StatefulSet
	Ready     int    `json:"ready"`
	Desired   int    `json:"desired"`
}

// K8sInfo holds cluster-level health data.
type K8sInfo struct {
	Nodes         []K8sNodeInfo     `json:"nodes"`
	Pods          []K8sPodInfo      `json:"pods"`
	Events        []K8sEvent        `json:"events,omitempty"`
	PVCs          []K8sPVCInfo      `json:"pvcs,omitempty"`
	Workloads     []K8sWorkloadInfo `json:"workloads,omitempty"`
	NodesNotReady int               `json:"nodes_not_ready"`
	PodsNotReady  int               `json:"pods_not_ready"`
	CrashLooping  int               `json:"crash_looping"`
	Pending       int               `json:"pending"`
	HighRestarts  int               `json:"high_restarts"`
	PVCsNotBound  int               `json:"pvcs_not_bound"`
	WorkloadsDown int               `json:"workloads_down"` // ready < desired
	Terminating   int               `json:"terminating"`    // stuck Terminating pods
	Detected      bool              `json:"detected"`
	KubeBin       string            `json:"kube_bin"`
	// OS-layer deep checks (only populated when --deep and running on k8s node)
	OSLayer      *K8sOSLayer `json:"os_layer,omitempty"`
	Status       string      `json:"status,omitempty"`
	StatusReason string      `json:"status_reason,omitempty"`
}

// K8sOSLayer holds OS-level diagnostics for the k8s node.
type K8sOSLayer struct {
	KubeletActive      bool     `json:"kubelet_active"`
	KubeletErrors      []string `json:"kubelet_errors,omitempty"`
	ContainerdActive   bool     `json:"containerd_active"`
	IPForwardEnabled   bool     `json:"ip_forward_enabled"`
	IPForwardChecked   bool     `json:"ip_forward_checked"`    // false when /proc unreadable — state unknown, not disabled
	KubeForwardChain   bool     `json:"kube_forward_chain"`    // iptables/nft KUBE-FORWARD rule
	FlannelSubnetOK    bool     `json:"flannel_subnet_ok"`     // /run/flannel/subnet.env present
	CNIBinsOK          bool     `json:"cni_bins_ok"`           // /opt/cni/bin/ populated
	FirewalldMasquOK   bool     `json:"firewalld_masq_ok"`     // masquerade enabled if firewalld
	CertExpirySoonDays int      `json:"cert_expiry_soon_days"` // 0 = OK, >0 = days to expiry
	CertExpiredNames   []string `json:"cert_expired_names,omitempty"`
}
