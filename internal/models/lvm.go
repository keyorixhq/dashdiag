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
	Name         string  `json:"name"`
	SizeGB       float64 `json:"size_gb"`
	FreeGB       float64 `json:"free_gb"`
	FreePct      float64 `json:"free_pct"`
	MissingPVs   int     `json:"missing_pvs,omitempty"` // count of PVs in error/missing state
	HasMountedLV bool    `json:"has_mounted_lv"`        // false = VG has no mounted LVs (leftover/inactive)
}

// LVMRaidLV represents a mirror or RAID logical volume.
type LVMRaidLV struct {
	Name      string  `json:"name"`
	VG        string  `json:"vg"`
	Type      string  `json:"type"`      // "mirror", "raid1", "raid5", etc.
	Degraded  bool    `json:"degraded"`  // one or more PVs failed
	Resyncing bool    `json:"resyncing"` // sync in progress
	SyncPct   float64 `json:"sync_pct"`  // 0–100
	SizeGB    float64 `json:"size_gb"`
}

// LVMInfo holds LVM health data for the system.
type LVMInfo struct {
	VGs       []LVMVG       `json:"vgs,omitempty"`
	ThinPools []LVMThinPool `json:"thin_pools,omitempty"`
	Snapshots []LVMSnapshot `json:"snapshots,omitempty"`
	RaidLVs   []LVMRaidLV   `json:"raid_lvs,omitempty"` // mirror/RAID LVs
	// RaidReadFailed is true only when the separate RAID-LV `lvs` query returned an
	// error. The VG/LV collection succeeding does NOT cover it; without this signal
	// a failed query left RaidLVs empty and a DEGRADED RAID LV was missed (there is
	// no other source for RAID-LV health). Inverted (failure, not success) so the
	// zero value means "no problem" — a healthy host never has to set it.
	RaidReadFailed bool `json:"raid_read_failed,omitempty"`
	// VGReadFailed/PVReadFailed/LVReadFailed are true when the corresponding
	// `vgs`/`pvs`/`lvs` query errored on a host where LVM IS installed (the collector
	// only runs these after the presence gate). Each runs independently; a failure
	// leaves its slice empty — or, for pvs, MissingPVs at 0, hiding a failed/removed
	// PV ("data at risk") while vgs still reports the VG fine — which would read as a
	// silent OK. Inverted (failure, not success) so the zero value means "read OK".
	VGReadFailed bool `json:"vg_read_failed,omitempty"`
	PVReadFailed bool `json:"pv_read_failed,omitempty"`
	LVReadFailed bool `json:"lv_read_failed,omitempty"`
	// PresenceReadFailed is true when the outer presence gate (`lvs --version`)
	// could not confirm one way or the other whether lvm2 is installed — the lvs
	// binary was found and ran but exited non-zero, as opposed to a clean
	// "binary not found" spawn failure. VGs/ThinPools/etc are then empty because
	// nothing was queried, not because there is genuinely no LVM. Never let that
	// read as a clean "no LVM".
	PresenceReadFailed bool `json:"presence_read_failed,omitempty"`
}
