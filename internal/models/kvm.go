package models

// KVMVMState is the libvirt domain state.
type KVMVMState string

const (
	KVMRunning  KVMVMState = "running"
	KVMPaused   KVMVMState = "paused"
	KVMShutOff  KVMVMState = "shut off"
	KVMCrashed  KVMVMState = "crashed"
	KVMShutDown KVMVMState = "shut down"
)

// KVMVM holds status for a single libvirt domain.
type KVMVM struct {
	Name         string     `json:"name"`
	ID           int        `json:"id"` // -1 when not running
	State        KVMVMState `json:"state"`
	AutoStart    bool       `json:"autostart"`
	VCPU         int        `json:"vcpu"`
	MaxMemMB     int        `json:"max_mem_mb"`
	UsedMemMB    int        `json:"used_mem_mb"`
	DiskIOError  bool       `json:"disk_io_error"`
	LastLogError string     `json:"last_log_error,omitempty"` // from /var/log/libvirt/qemu/
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
	Detected         bool             `json:"detected"` // libvirt found and running
	LibvirtVer       string           `json:"libvirt_ver,omitempty"`
	QEMUVer          string           `json:"qemu_ver,omitempty"`
	VMs              []KVMVM          `json:"vms"`
	Networks         []KVMNetwork     `json:"networks"`
	StoragePools     []KVMStoragePool `json:"storage_pools"`
	VMsRunning       int              `json:"vms_running"`
	VMsPaused        int              `json:"vms_paused"`
	VMsCrashed       int              `json:"vms_crashed"`
	VMsDownAutostart int              `json:"vms_down_autostart"` // shut off with autostart=yes
	NetworksInactive int              `json:"networks_inactive"`
	PoolsInactive    int              `json:"pools_inactive"`
	PoolsNearFull    int              `json:"pools_near_full"` // >85% used
	DiskIOErrors     int              `json:"disk_io_errors"`
	Status           string           `json:"status,omitempty"`
	StatusReason     string           `json:"status_reason,omitempty"`
}
