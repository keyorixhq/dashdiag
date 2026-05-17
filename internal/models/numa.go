package models

// NUMANode is one NUMA memory node.
type NUMANode struct {
	ID        int     `json:"id"`
	MemGB     float64 `json:"mem_gb"`
	MemFreeGB float64 `json:"mem_free_gb"`
	CPUs      []int   `json:"cpus,omitempty"`
}

// NUMAInfo holds NUMA topology health.
type NUMAInfo struct {
	Available    bool       `json:"available"`
	NodeCount    int        `json:"node_count"`
	Nodes        []NUMANode `json:"nodes,omitempty"`
	Imbalanced   bool       `json:"imbalanced"` // one node >40% more memory than others
	Status       string     `json:"status,omitempty"`
	StatusReason string     `json:"status_reason,omitempty"`
}
