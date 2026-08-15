package models

// HWRaidInfo reports the health of a HARDWARE RAID controller (LSI/Broadcom MegaRAID
// and Dell PERC via storcli/perccli, HPE Smart Array via ssacli). This is the false-OK
// hardware RAID exists to cause: a degraded virtual drive or a failed physical disk
// behind the controller is invisible to the OS — /proc/mdstat, LVM and ZFS all see one
// healthy block device. Only the controller's own CLI knows the array is running
// without redundancy. Gated on a controller CLI being present; silent otherwise.
type HWRaidInfo struct {
	Available   bool               `json:"available"` // a controller CLI is present AND at least one controller responded
	Tool        string             `json:"tool,omitempty"`
	Controllers []HWRaidController `json:"controllers,omitempty"`
	NeedsRoot   bool               `json:"needs_root,omitempty"`  // CLI present but its output requires root — could not read
	ReadFailed  bool               `json:"read_failed,omitempty"` // CLI present, ran, but output was unparseable — NOT assumed healthy
}

// HWRaidController is one RAID controller and the drives behind it.
type HWRaidController struct {
	ID             int        `json:"id"`
	Model          string     `json:"model,omitempty"`
	VirtualDrives  []HWRaidVD `json:"virtual_drives,omitempty"`
	PhysicalDrives []HWRaidPD `json:"physical_drives,omitempty"`
	BBUStatus      string     `json:"bbu_status,omitempty"` // cache battery / capacitor health, verbatim
	BBUDegraded    bool       `json:"bbu_degraded,omitempty"`
	// BBUStatusUnreadable is true when a BBU/CacheVault entry IS present but
	// its State field couldn't be read (schema drift) — distinct from no
	// entry at all (genuinely no battery-backed cache fitted), which stays
	// silent.
	BBUStatusUnreadable bool `json:"bbu_status_unreadable,omitempty"`
}

// HWRaidVD is a virtual drive (logical volume the controller presents to the OS).
type HWRaidVD struct {
	Name       string `json:"name"`
	RaidLevel  string `json:"raid_level,omitempty"`
	State      string `json:"state"` // normalized: Optimal / Degraded / Partially Degraded / Offline / Rebuilding
	Degraded   bool   `json:"degraded"`
	Offline    bool   `json:"offline"`
	Rebuilding bool   `json:"rebuilding"`
}

// HWRaidPD is a physical drive attached to the controller.
type HWRaidPD struct {
	Location   string `json:"location"` // enclosure:slot (storcli) or port:box:bay (ssacli)
	State      string `json:"state"`    // normalized: Online / Failed / Rebuilding / Offline / Unconfigured Bad / Predictive Failure
	Failed     bool   `json:"failed"`
	Rebuilding bool   `json:"rebuilding"`
	Predictive bool   `json:"predictive_failure"`
}
