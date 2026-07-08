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
	NodeName       string `json:"node_name,omitempty"`       // set for Unknown-status pods — the node it was scheduled on
	OwnerKind      string `json:"owner_kind,omitempty"`      // set for Unknown-status pods, e.g. "StatefulSet"
	OwnerName      string `json:"owner_name,omitempty"`      // set for Unknown-status pods
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
	UnknownStatus int               `json:"unknown_status"` // pods in phase Unknown — node likely unreachable
	PVCsNotBound  int               `json:"pvcs_not_bound"`
	WorkloadsDown int               `json:"workloads_down"` // ready < desired
	Terminating   int               `json:"terminating"`    // stuck Terminating pods
	Detected      bool              `json:"detected"`
	// APIReachable is true only when at least one cluster query (nodes/pods)
	// actually succeeded. kubectl/k3s being present (Detected) does NOT mean the
	// API answered — a down API server, bad kubeconfig, or missing RBAC makes
	// every query fail and leaves all the counts at zero, which would otherwise
	// read as a healthy cluster (false-OK). The health layer surfaces
	// Detected && !APIReachable as "health not verified".
	APIReachable bool   `json:"api_reachable"`
	KubeBin      string `json:"kube_bin"`
	// Distribution is the Kubernetes flavor in use ("rke2", "k3s", "microk8s",
	// "kubeadm"), best-effort from on-disk markers. Empty when undetermined.
	Distribution string `json:"distribution,omitempty"`
	// OS-layer deep checks (only populated when --deep and running on k8s node)
	OSLayer      *K8sOSLayer `json:"os_layer,omitempty"`
	Status       string      `json:"status,omitempty"`
	StatusReason string      `json:"status_reason,omitempty"`
}

// RancherInfo reports Rancher management-plane health on a cluster where Rancher is
// installed (the cattle-system namespace exists). Silent on clusters without Rancher.
type RancherInfo struct {
	Available      bool `json:"available"`      // cattle-system namespace present
	ServerReady    int  `json:"server_ready"`   // ready replicas of the rancher deployment
	ServerDesired  int  `json:"server_desired"` // desired replicas
	WebhookReady   int  `json:"webhook_ready"`
	WebhookDesired int  `json:"webhook_desired"`
}

// K8sOSLayer holds OS-level diagnostics for the k8s node.
type K8sOSLayer struct {
	KubeletActive       bool     `json:"kubelet_active"`
	KubeletChecked      bool     `json:"kubelet_checked"` // false on a kubectl-only client host (no on-disk node marker) — state not applicable
	KubeletErrors       []string `json:"kubelet_errors,omitempty"`
	ContainerdActive    bool     `json:"containerd_active"`
	ContainerdChecked   bool     `json:"containerd_checked"` // same gate as KubeletChecked
	IPForwardEnabled    bool     `json:"ip_forward_enabled"`
	IPForwardChecked    bool     `json:"ip_forward_checked"`        // false when /proc unreadable — state unknown, not disabled
	KubeForwardChain    bool     `json:"kube_forward_chain"`        // iptables/nft KUBE-FORWARD rule
	KubeForwardChecked  bool     `json:"kube_forward_checked"`      // false when neither nft nor iptables could be run — state unknown
	KubeServicesChecked bool     `json:"kube_services_checked"`     // false = kube-proxy pod not found / tool unavailable — not applicable
	KubeServicesCount   int      `json:"kube_services_count"`       // KUBE-SERVICES entries (iptables mode) or TCP virtual servers (ipvs mode); meaningless unless KubeProxyMode is "iptables"/"ipvs"
	KubeSvcChainsCount  int      `json:"kube_svc_chains_count"`     // KUBE-SVC- per-service chains (iptables mode only) — supplementary evidence, no independent verdict
	KubeProxyMode       string   `json:"kube_proxy_mode,omitempty"` // "iptables" | "ipvs" | "nft" | "" (unknown/not-applicable)
	FlannelSubnetOK     bool     `json:"flannel_subnet_ok"`         // /run/flannel/subnet.env present
	FlannelInUse        bool     `json:"flannel_in_use"`            // flannel is the configured CNI (else subnet.env absence is normal)
	CNIBinsOK           bool     `json:"cni_bins_ok"`               // /opt/cni/bin/ populated
	CNIChecked          bool     `json:"cni_checked"`               // false when /opt/cni/bin unreadable (permission) — state unknown
	FirewalldMasquOK    bool     `json:"firewalld_masq_ok"`         // masquerade enabled if firewalld
	FirewalldChecked    bool     `json:"firewalld_checked"`         // false unless firewalld.service is actually active — state not applicable
	CertExpirySoon      bool     `json:"cert_expiry_soon"`          // true when a cert expires within 30d — companion flag so 0 days (within 24h) isn't read as the zero-value "none"
	CertExpirySoonDays  int      `json:"cert_expiry_soon_days"`     // days to soonest expiry when CertExpirySoon; 0 = within 24h. Meaningless unless CertExpirySoon
	CertExpiredNames    []string `json:"cert_expired_names,omitempty"`
}
