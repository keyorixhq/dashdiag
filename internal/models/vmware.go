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
}
