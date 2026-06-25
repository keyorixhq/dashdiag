package models

// DriveType represents the physical storage device type.
type DriveType string

const (
	DriveTypeNVMe DriveType = "NVMe"
	DriveTypeSSD  DriveType = "SSD"
	DriveTypeHDD  DriveType = "HDD"
)

// SMARTInfo holds S.M.A.R.T. health summary for a physical disk.
type SMARTInfo struct {
	Device          string `json:"device"`
	Healthy         bool   `json:"healthy"`         // SMART overall PASSED
	PercentUsed     int    `json:"percent_used"`    // NVMe wear: 0–100%
	AvailableSpare  int    `json:"available_spare"` // NVMe spare %
	Temperature     int    `json:"temperature_c"`   // celsius
	MediaErrors     int64  `json:"media_errors"`    // NVMe media/data integrity errors
	PowerOnHours    int64  `json:"power_on_hours,omitempty"`
	UnsafeShutdowns int64  `json:"unsafe_shutdowns,omitempty"`
	PowerCycles     int64  `json:"power_cycles,omitempty"`
	Error           string `json:"error,omitempty"` // if smartctl unavailable
}

// NoRealTelemetry reports a SMART verdict that PASSED but carries only
// not-reported sentinels (no temperature, zero spare/wear/errors/hours/cycles) —
// the signature of a virtual/cloud block device (e.g. AWS EBS) that answers the
// SMART health query but passes through no real on-device telemetry. Rendering
// such a drive as a confident "PASSED" overstates what was actually measured;
// the standalone `dsd disk` view should mirror `dsd health`, which already flags
// this case (NVMeNoRealData). A genuine drive always reports a temperature and a
// non-zero spare, so this never matches a real (even brand-new) disk.
func (s SMARTInfo) NoRealTelemetry() bool {
	return s.Healthy &&
		s.Temperature <= 0 && s.AvailableSpare == 0 && s.PercentUsed == 0 &&
		s.MediaErrors == 0 && s.PowerOnHours == 0 && s.PowerCycles == 0 &&
		s.UnsafeShutdowns == 0
}

// PhysicalDrive is a block device detected on the system.
type PhysicalDrive struct {
	Name   string     `json:"name"` // e.g. "nvme0n1", "sda"
	SizeGB float64    `json:"size_gb"`
	Type   DriveType  `json:"type"` // NVMe, SSD, HDD
	Model  string     `json:"model,omitempty"`
	Mounts []string   `json:"mounts,omitempty"` // partition→mount pairs
	SMART  *SMARTInfo `json:"smart,omitempty"`
}

// DiskIOStat holds I/O rate for a single block device (deep mode).
type DiskIOStat struct {
	Device   string  `json:"device"`
	ReadMBs  float64 `json:"read_mbs"`
	WriteMBs float64 `json:"write_mbs"`
	UtilPct  float64 `json:"util_pct"`
}

type FilesystemInfo struct {
	Mount         string  `json:"mount"`
	Device        string  `json:"device"`
	FSType        string  `json:"fs_type"`
	TotalGB       float64 `json:"total_gb"`
	UsedGB        float64 `json:"used_gb"`
	FreeGB        float64 `json:"free_gb"`
	UsedPct       float64 `json:"used_pct"`
	InodesUsedPct float64 `json:"inodes_used_pct"`
	ReadOnly      bool    `json:"read_only"`
	Status        string  `json:"status"`
	StatusReason  string  `json:"status_reason"`
}

type DiskInfo struct {
	Filesystems []FilesystemInfo `json:"filesystems"`
	Drives      []PhysicalDrive  `json:"drives,omitempty"`
	ZFSPools    []ZFSPool        `json:"zfs_pools,omitempty"` // from models/zfs.go
	// ZFSListReadFailed is true when a live ZFS mount exists (zfsGate) but
	// `zpool list` errored, so ZFSPools is empty for a reason other than "no pools".
	ZFSListReadFailed bool          `json:"zfs_list_read_failed,omitempty"`
	BtrfsVolumes      []BtrfsVolume `json:"btrfs_volumes,omitempty"`
	IOStats           []DiskIOStat  `json:"io_stats,omitempty"` // deep only
	SteamOS           *SteamOSDisk  `json:"steamos,omitempty"`  // SteamOS-only partition layout (Spec 19)
	Status            string        `json:"status"`
	StatusReason      string        `json:"status_reason"`
}

// BtrfsVolume holds health data for a mounted btrfs filesystem.
type BtrfsVolume struct {
	UUID         string     `json:"uuid"`
	MountPoint   string     `json:"mount_point"`
	TotalDevices int        `json:"total_devices"`
	MissingDevs  int        `json:"missing_devices"`
	Devices      []BtrfsDev `json:"devices"`
	Status       string     `json:"status"` // "healthy", "degraded", "missing"
	StatusReason string     `json:"status_reason,omitempty"`
	// StatsRead is true only when `btrfs device stats` was read successfully. When it
	// fails (permission denied / error), the per-device error counters stay 0 and
	// Status stays "healthy" — which would read as a silent OK even though corruption/
	// I/O counters were never inspected. Lets the verdict say "counters not read".
	StatsRead bool `json:"stats_read,omitempty"`
	// DevReadUnverified is true when `btrfs filesystem show` flagged a REAL device path
	// MISSING on a non-root run — btrfs couldn't open the block device for lack of
	// privilege (it prints `size 0 ... MISSING`), which is NOT a missing device. The
	// verdict then says "device state unverified — run as root" instead of a false
	// DEGRADED CRIT. (A genuinely absent device shows the `<missing disk>` placeholder.)
	DevReadUnverified bool `json:"dev_read_unverified,omitempty"`
}

// BtrfsDev is one device in a btrfs filesystem.
type BtrfsDev struct {
	DevID       int    `json:"devid"`
	Path        string `json:"path"` // "<missing disk>" when absent
	Missing     bool   `json:"missing"`
	ReadErrs    int64  `json:"read_errs"`
	WriteErrs   int64  `json:"write_errs"`
	CorruptErrs int64  `json:"corrupt_errs"`
	GenErrs     int64  `json:"generation_errs"`
	FlushErrs   int64  `json:"flush_errs"`
}
