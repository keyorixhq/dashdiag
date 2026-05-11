package models

// K8sNodeInfo holds status for a single k8s node.
type K8sNodeInfo struct {
	Name    string `json:"name"`
	Status  string `json:"status"` // Ready, NotReady, Unknown
	Roles   string `json:"roles"`
	Age     string `json:"age"`
	Version string `json:"version"`
}

// K8sPodInfo holds status for a single pod.
type K8sPodInfo struct {
	Namespace string `json:"namespace"`
	Name      string `json:"name"`
	Ready     string `json:"ready"`  // e.g. "1/1"
	Status    string `json:"status"` // Running, CrashLoopBackOff, Pending etc
	Restarts  int    `json:"restarts"`
	Age       string `json:"age"`
}

// K8sInfo holds cluster-level health data.
type K8sInfo struct {
	Nodes         []K8sNodeInfo `json:"nodes"`
	Pods          []K8sPodInfo  `json:"pods"`
	NodesNotReady int           `json:"nodes_not_ready"`
	PodsNotReady  int           `json:"pods_not_ready"`
	CrashLooping  int           `json:"crash_looping"`
	Pending       int           `json:"pending"`
	HighRestarts  int           `json:"high_restarts"`
	Detected      bool          `json:"detected"`
	KubeBin       string        `json:"kube_bin"`
	Status        string        `json:"status,omitempty"`
	StatusReason  string        `json:"status_reason,omitempty"`
}
