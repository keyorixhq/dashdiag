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
//
// internal-models-03-01: this used to require ALL SEVEN fields to be exactly
// the sentinel value — a single stray non-zero field (a parser quirk, or a
// virtual device that happens to pass through one real counter, e.g. a
// power-cycle count) defeated the detector entirely and produced a confident
// "PASSED" for a drive that reported almost nothing real. Instead, tolerate at
// most ONE non-zero field (6-of-7 sentinel) before still calling it
// no-real-telemetry: a lone stray field is far more consistent with a
// virtual/passthrough quirk than with a genuine drive, while two or more
// non-zero fields is a strong signal of actual on-device telemetry.
//
// internal-models-03-01 layering note: this is a method with real
// classification logic on a models-layer struct, which conflicts with this
// package's "dumb structs only, no methods, no logic" contract (see
// CLAUDE.md's Models layer contract). It predates this fix and is left in
// place here — see the fix report for why relocating it to internal/analysis
// (as its NVMeDevice sibling NVMeNoRealData already does) is out of scope for
// this change.
func (s SMARTInfo) NoRealTelemetry() bool {
	if !s.Healthy {
		return false
	}
	const totalFields = 7
	zero := 0
	if s.Temperature <= 0 {
		zero++
	}
	if s.AvailableSpare == 0 {
		zero++
	}
	if s.PercentUsed == 0 {
		zero++
	}
	if s.MediaErrors == 0 {
		zero++
	}
	if s.PowerOnHours == 0 {
		zero++
	}
	if s.PowerCycles == 0 {
		zero++
	}
	if s.UnsafeShutdowns == 0 {
		zero++
	}
	// Allow at most one non-zero (sentinel) field.
	return zero >= totalFields-1
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
	// DeviceSizeGB is the size of the backing block device (partition / LV), read
	// from /sys/class/block/<kname>/size, in decimal GB. 0 when unknown (non-Linux,
	// or a device with no sysfs size node). A DeviceSizeGB meaningfully larger than
	// TotalGB means the disk/partition/LV was grown but the filesystem was never
	// resized (growpart/resize2fs/xfs_growfs forgotten) — the extra space is unusable.
	DeviceSizeGB float64 `json:"device_size_gb,omitempty"`
	// BusyProcesses lists PIDs with files open on this filesystem — populated only
	// when the mount is near-full or unexpectedly read-only (see the collector's
	// needsBusyCheck gate), so an admin blocked by "device or resource busy" on an
	// unmount knows what to stop first. Nil for healthy mounts (no scan runs).
	BusyProcesses []FSBusyProcess `json:"busy_processes,omitempty"`
	// BusyCheckNeedsRoot is true when the busy-process scan ran unprivileged: both
	// fuser and the /proc/*/fd fallback can only see file descriptors of processes
	// owned by the current user, so PIDs owned by other users are silently
	// invisible. Set whenever a scan was attempted, so a non-root run never reads
	// as "confirmed only N processes have this open".
	BusyCheckNeedsRoot bool `json:"busy_check_needs_root,omitempty"`
}

// FSBusyProcess is one process holding an open file on a busy/near-full
// filesystem — see FilesystemInfo.BusyProcesses.
type FSBusyProcess struct {
	PID     int    `json:"pid"`
	Command string `json:"command"`
	User    string `json:"user"`
	Write   bool   `json:"write"` // holds the file open for writing, not just read
}

type DiskInfo struct {
	Filesystems []FilesystemInfo `json:"filesystems"`
	Drives      []PhysicalDrive  `json:"drives,omitempty"`
	// DrivesListUnreadable is true (macOS only) when `diskutil list` itself
	// failed or returned nothing — distinct from a genuine zero-physical-
	// drives host, which cannot actually occur on real Mac hardware. Without
	// this, an enumeration failure and "0 drives" produce the identical empty
	// Drives slice and zero SMART insights either way.
	DrivesListUnreadable bool      `json:"drives_list_unreadable,omitempty"`
	ZFSPools             []ZFSPool `json:"zfs_pools,omitempty"` // from models/zfs.go
	// ZFSListReadFailed is true when a live ZFS mount exists (zfsGate) but
	// `zpool list` errored, so ZFSPools is empty for a reason other than "no pools".
	ZFSListReadFailed bool          `json:"zfs_list_read_failed,omitempty"`
	BtrfsVolumes      []BtrfsVolume `json:"btrfs_volumes,omitempty"`
	IOStats           []DiskIOStat  `json:"io_stats,omitempty"` // deep only
	SteamOS           *SteamOSDisk  `json:"steamos,omitempty"`  // SteamOS-only partition layout (Spec 19)
	// ImmutableRootFS is true when the host mounts / read-only BY DESIGN (ostree,
	// transactional-update/MicroOS, SteamOS). Internal plumbing only (json:"-", out of
	// the --json contract; recomputed by the collector on replay) — lets the
	// read-only-mount heuristic skip the expected ro root instead of false-WARNing.
	ImmutableRootFS bool   `json:"-"`
	Status          string `json:"status"`
	StatusReason    string `json:"status_reason"`
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
	// ShowRead is false when `btrfs filesystem show` itself failed entirely (binary
	// missing, timeout, permission denied, OOM on a large multi-device fs) — distinct
	// from every other field above, which assumes the command at least produced
	// output. A false ShowRead means NOTHING about this volume was verified; it must
	// not render as the zero-value "healthy" default.
	ShowRead bool `json:"show_read,omitempty"`
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
