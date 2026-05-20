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
	Filesystems  []FilesystemInfo `json:"filesystems"`
	Drives       []PhysicalDrive  `json:"drives,omitempty"`
	ZFSPools     []ZFSPool        `json:"zfs_pools,omitempty"` // from models/zfs.go
	BtrfsVolumes []BtrfsVolume    `json:"btrfs_volumes,omitempty"`
	IOStats      []DiskIOStat     `json:"io_stats,omitempty"` // deep only
	Status       string           `json:"status"`
	StatusReason string           `json:"status_reason"`
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
}

// BtrfsDev is one device in a btrfs filesystem.
type BtrfsDev struct {
	DevID       int    `json:"devid"`
	Path        string `json:"path"` // "<missing disk>" when absent
	Missing     bool   `json:"missing"`
	ReadErrs    int64  `json:"read_errs"`
	WriteErrs   int64  `json:"write_errs"`
	CorruptErrs int64  `json:"corrupt_errs"`
}
