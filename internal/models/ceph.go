package models

// CephOSD is one Ceph OSD daemon.
type CephOSD struct {
	ID    int    `json:"id"`
	State string `json:"state"` // up, down
	In    bool   `json:"in"`    // in = participates in data placement
}

// CephInfo holds Ceph cluster health from `ceph health detail`.
type CephInfo struct {
	Available    bool      `json:"available"`
	Health       string    `json:"health"` // HEALTH_OK, HEALTH_WARN, HEALTH_ERR
	OSDTotal     int       `json:"osd_total"`
	OSDUp        int       `json:"osd_up"`
	OSDIn        int       `json:"osd_in"`
	Summary      []string  `json:"summary,omitempty"` // human-readable health messages
	OSDs         []CephOSD `json:"osds,omitempty"`
	Status       string    `json:"status,omitempty"`
	StatusReason string    `json:"status_reason,omitempty"`
}
