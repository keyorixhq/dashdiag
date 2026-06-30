package models

// HAInfo reports Pacemaker/Corosync high-availability cluster health: quorum, node
// membership, resource state, and whether fencing (STONITH) is configured. Gated on
// the cluster stack being installed, so it's silent on every non-cluster host.
type HAInfo struct {
	Available        bool     `json:"available"`    // pacemaker/corosync installed
	Running          bool     `json:"running"`      // pacemakerd + corosync active
	QuorumKnown      bool     `json:"quorum_known"` // quorum could be read (else unknown — non-root)
	Quorate          bool     `json:"quorate"`      // the partition holds quorum
	NodesOnline      int      `json:"nodes_online"`
	NodesTotal       int      `json:"nodes_total"`
	OfflineNodes     []string `json:"offline_nodes,omitempty"`
	StatusReadable   bool     `json:"status_readable"` // crm_mon could be read (else non-root — unknown)
	ResourcesStarted int      `json:"resources_started"`
	ResourcesTotal   int      `json:"resources_total"`
	FailedResources  []string `json:"failed_resources,omitempty"`
	StoppedResources []string `json:"stopped_resources,omitempty"`
	StonithEnabled   bool     `json:"stonith_enabled"`
	StonithDevices   int      `json:"stonith_devices"` // configured fence devices
}
