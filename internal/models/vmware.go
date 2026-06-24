package models

// VMwareInfo reports VMware-guest configuration health. Populated only when
// running as a Linux guest under VMware (gate: DMI sys_vendor/product_name);
// nil/zero on every other platform so it adds no noise elsewhere.
//
// Scope is guest-side Linux only — the things a guest can see and fix about its
// own configuration. ESXi hypervisor internals and the vSwitch/fabric are out of
// scope (not visible from inside the guest).
type VMwareInfo struct {
	IsGuest     bool   `json:"is_guest"`
	ProductName string `json:"product_name,omitempty"` // DMI product_name, e.g. "VMware7,1"

	// open-vm-tools (guest tools): required for time sync, quiesced snapshots /
	// backups, graceful guest shutdown, the balloon driver, and host-side guest
	// awareness (IP reporting, vMotion quiescing).
	ToolsInstalled bool `json:"tools_installed"`
	ToolsRunning   bool `json:"tools_running"`

	// Paravirtual driver usage. Emulated NICs (e1000/e1000e/vlance/pcnet) burn
	// host CPU and cap throughput versus the paravirtual vmxnet3.
	NICDrivers   map[string]string `json:"nic_drivers,omitempty"`   // iface -> driver
	EmulatedNICs []string          `json:"emulated_nics,omitempty"` // ifaces on emulated drivers

	PVSCSILoaded  bool `json:"pvscsi_loaded"`  // vmw_pvscsi (paravirtual disk) module present
	BalloonLoaded bool `json:"balloon_loaded"` // vmw_balloon module present (host can reclaim memory)

	// Host-imposed resource pressure/limits reported by `vmware-toolbox-cmd stat`
	// (requires open-vm-tools running). Visible from inside the guest and the
	// memory/CPU analog of CPU steal time — the strongest guest-side evidence
	// that a "slow VM" is the host's doing, not the guest's.
	StatAvailable bool `json:"stat_available"`          // toolbox-cmd stat counters were readable
	BalloonMB     int  `json:"balloon_mb"`              // RAM the host is reclaiming via the balloon (>0 = host memory pressure)
	HostSwapMB    int  `json:"host_swap_mb"`            // guest RAM the host has swapped to disk (>0 = severe host memory pressure)
	MemLimitMB    int  `json:"mem_limit_mb,omitempty"`  // host-imposed memory cap, MB (0 = unlimited)
	CPULimitMHz   int  `json:"cpu_limit_mhz,omitempty"` // host-imposed CPU cap, MHz (0 = unlimited)

	// SCSI disk command timeouts (seconds), per /sys/block/sd*/device/timeout.
	// VMware recommends 180s so a guest survives a vMotion / storage-failover
	// stun without its filesystem going read-only; the kernel default is 30s.
	SCSITimeouts    map[string]int `json:"scsi_timeouts,omitempty"`     // disk -> timeout seconds
	LowSCSITimeouts []string       `json:"low_scsi_timeouts,omitempty"` // disks below the 180s recommendation

	// disk.EnableUUID — when FALSE on a vSphere VM, paravirtual-SCSI disks expose
	// no SCSI page 0x83 / stable hardware ID, so /dev/disk/by-id and the vSphere
	// CSI driver cannot reliably identify them (k8s persistent volumes mis-bind).
	// Detected guest-side: a SCSI sd* disk with an empty /sys/.../device/wwid is the
	// EnableUUID=FALSE signature. (IDE/SATA disks carry an ATA serial regardless;
	// NVMe always has an eui — neither is affected, so only sd* is examined.)
	SCSIDisksChecked bool     `json:"scsi_disks_checked"`           // at least one sd* disk was examined
	DisksNoStableID  []string `json:"disks_no_stable_id,omitempty"` // sd* disks with no wwid → EnableUUID likely off

	// Per-vmxnet3-NIC driver-internal counters from `ethtool -S` that the standard
	// /sys/class/net statistics (already covered by the Network collector) do NOT
	// expose: RX buffer-allocation failures and TX/RX ring exhaustion. Non-zero
	// above a ratio floor means the driver rings are undersized for the workload —
	// tunable with `ethtool -G`. Empty when no vmxnet3 NIC or ethtool is absent.
	VMXNETStats []VMXNETStats `json:"vmxnet_stats,omitempty"`
}

// VMXNETStats holds the vmxnet3-specific drop/exhaustion counters for one NIC,
// with the total rx/tx packet counts so the verdict can be rate-based (a flat
// cumulative count would false-WARN on a long-uptime host).
type VMXNETStats struct {
	Iface          string `json:"iface"`
	RxBufAllocFail uint64 `json:"rx_buf_alloc_fail"` // "rx buf alloc fail" — RX buffers couldn't be allocated
	RxOOB          uint64 `json:"rx_oob"`            // "pkts rx OOB" — RX ring out of buffers
	TxRingFull     uint64 `json:"tx_ring_full"`      // "ring full" — TX descriptor ring exhausted
	RxPackets      uint64 `json:"rx_packets"`        // total RX packets (denominator for the rate)
	TxPackets      uint64 `json:"tx_packets"`        // total TX packets (denominator for the rate)
}
