package models

// LVMThinPool represents a thin-provisioned LVM pool within a volume group.
// Thin pool exhaustion (data or metadata) silently freezes all VMs writing to it.
type LVMThinPool struct {
	Name    string  `json:"name"`     // e.g. "data"
	VG      string  `json:"vg"`       // e.g. "pve"
	DataPct float64 `json:"data_pct"` // data space used %
	MetaPct float64 `json:"meta_pct"` // metadata space used %
	SizeGB  float64 `json:"size_gb"`
}

// LVMSnapshot represents an LVM snapshot LV.
// When the COW table fills, the snapshot becomes invalid.
type LVMSnapshot struct {
	Name    string  `json:"name"`
	VG      string  `json:"vg"`
	Origin  string  `json:"origin"`   // the LV being snapshotted
	DataPct float64 `json:"data_pct"` // COW table used %
}

// LVMVG represents a volume group with its free space.
type LVMVG struct {
	Name       string  `json:"name"`
	SizeGB     float64 `json:"size_gb"`
	FreeGB     float64 `json:"free_gb"`
	FreePct    float64 `json:"free_pct"`
	MissingPVs int     `json:"missing_pvs,omitempty"` // count of PVs in error/missing state
}

// LVMInfo holds LVM health data for the system.
type LVMInfo struct {
	VGs       []LVMVG       `json:"vgs,omitempty"`
	ThinPools []LVMThinPool `json:"thin_pools,omitempty"`
	Snapshots []LVMSnapshot `json:"snapshots,omitempty"`
}
