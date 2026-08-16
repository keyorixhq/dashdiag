package models

// KVMVMState is the libvirt domain state.
type KVMVMState string

const (
	KVMRunning  KVMVMState = "running"
	KVMPaused   KVMVMState = "paused"
	KVMShutOff  KVMVMState = "shut off"
	KVMCrashed  KVMVMState = "crashed"
	KVMShutDown KVMVMState = "shut down"
	// Abnormal non-running states virsh dominfo can report that aren't a clean
	// "shut off": a guest stuck suspended-to-RAM, wedged mid-shutdown, or in the
	// legacy idle/blocked states. Not running, not cleanly stopped → a fault.
	KVMPMSuspended KVMVMState = "pmsuspended"
	KVMInShutdown  KVMVMState = "in shutdown"
	KVMIdle        KVMVMState = "idle"
	KVMBlocked     KVMVMState = "blocked"
)

// KVMVM holds status for a single libvirt domain.
type KVMVM struct {
	Name        string     `json:"name"`
	ID          int        `json:"id"` // -1 when not running
	State       KVMVMState `json:"state"`
	AutoStart   bool       `json:"autostart"`
	VCPU        int        `json:"vcpu"`
	MaxMemMB    int        `json:"max_mem_mb"`
	UsedMemMB   int        `json:"used_mem_mb"`
	DiskIOError bool       `json:"disk_io_error"`
	// DiskErrorCheckFailed is true when `virsh domblkerror` itself failed to
	// run (not "ran and found no errors") — DiskIOError stays false either
	// way, so this is the only signal that distinguishes "verified clean"
	// from "couldn't verify."
	DiskErrorCheckFailed bool   `json:"disk_error_check_failed,omitempty"`
	LastLogError         string `json:"last_log_error,omitempty"` // from /var/log/libvirt/qemu/

	// Deep-only: parsed from `virsh dumpxml` (works for shut-off VMs too, since it
	// reads the persistent definition rather than live device state).
	EmulatedNICs    []string `json:"emulated_nics,omitempty"`     // "<mac> (<model>)" on a non-VirtIO NIC model
	EmulatedDisks   []string `json:"emulated_disks,omitempty"`    // "<dev> (<bus>)" on a non-VirtIO disk bus
	MissingDiskPath string   `json:"missing_disk_path,omitempty"` // file-backed disk whose backing file is gone
}

// KVMNetwork holds status for a libvirt virtual network.
type KVMNetwork struct {
	Name      string `json:"name"`
	State     string `json:"state"` // active, inactive
	Autostart bool   `json:"autostart"`
	BridgeUp  bool   `json:"bridge_up"` // virbr* link state
	Bridge    string `json:"bridge,omitempty"`
}

// KVMStoragePool holds capacity info for a libvirt storage pool.
type KVMStoragePool struct {
	Name        string  `json:"name"`
	State       string  `json:"state"` // active, inactive
	CapacityGB  float64 `json:"capacity_gb"`
	AvailableGB float64 `json:"available_gb"`
	UsedPct     float64 `json:"used_pct"`
}

// KVMInfo is the output of `dsd kvm`.
type KVMInfo struct {
	Detected              bool             `json:"detected"` // libvirt found and running
	LibvirtVer            string           `json:"libvirt_ver,omitempty"`
	QEMUVer               string           `json:"qemu_ver,omitempty"`
	VMs                   []KVMVM          `json:"vms"`
	Networks              []KVMNetwork     `json:"networks"`
	StoragePools          []KVMStoragePool `json:"storage_pools"`
	VMsRunning            int              `json:"vms_running"`
	VMsPaused             int              `json:"vms_paused"`
	VMsCrashed            int              `json:"vms_crashed"`
	VMsDownAutostart      int              `json:"vms_down_autostart"` // shut off with autostart=yes
	VMsAbnormal           int              `json:"vms_abnormal"`       // pmsuspended / in shutdown / idle / blocked
	VMsUnreadable         int              `json:"vms_unreadable"`     // virsh dominfo failed — state unknown
	NetworksInactive      int              `json:"networks_inactive"`
	PoolsInactive         int              `json:"pools_inactive"`
	PoolsNearFull         int              `json:"pools_near_full"`   // >85% used
	PoolsCapUnknown       int              `json:"pools_cap_unknown"` // virsh pool-info failed — capacity/usage unknown, may be near-full undetected
	DiskIOErrors          int              `json:"disk_io_errors"`
	DiskErrorChecksFailed int              `json:"disk_error_checks_failed,omitempty"` // virsh domblkerror failed — I/O error status unknown for these VMs
	Status                string           `json:"status,omitempty"`
	StatusReason          string           `json:"status_reason,omitempty"`
}
