package models

// AzureInfo reports guest-side health for a Linux VM on Microsoft Azure — the
// Azure-specific signals a guest can see about itself that the generic collectors
// miss. Populated only on Azure (gate: DMI chassis asset tag); nil/zero everywhere
// else so it adds no noise off Azure.
//
// Scope is strictly guest-side, no Azure API credentials: kernel/driver topology
// (the Hyper-V synthetic NICs + Accelerated-Networking SR-IOV VFs) and local daemon
// state (the Azure Linux agent, the Hyper-V PTP time source). The headline failure it
// targets is the Accelerated-Networking false-green: AN shows "enabled" in the portal
// but the VF never attached, so traffic silently rides the slow synthetic path.
//
// Unlike AWS EBS, Azure exposes no guest-side disk-throttle telemetry (managed disks
// are SCSI via hv_storvsc, with no vendor log page), so there is deliberately no
// disk-throttle field here — that signal lives only in the Azure API/metrics.
type AzureInfo struct {
	IsAzure bool `json:"is_azure"`

	// --- Accelerated Networking (SR-IOV) datapath ---
	// On Azure, Accelerated Networking bonds a Mellanox/MANA VF transparently under
	// the synthetic hv_netvsc NIC. A VF present + bonded + up means the fast datapath
	// is live; hv_netvsc with no VF means traffic is on the synthetic path.
	SyntheticNICs []string  `json:"synthetic_nics,omitempty"` // hv_netvsc interfaces
	AN            []ANIface `json:"accelerated_networking,omitempty"`
	HasVF         bool      `json:"has_vf"` // at least one accelerated VF was found

	// --- Hyper-V synthetic drivers (recognition/context) ---
	NetvscLoaded  bool `json:"netvsc_loaded"`  // hv_netvsc (synthetic NIC)
	StorvscLoaded bool `json:"storvsc_loaded"` // hv_storvsc (synthetic SCSI/disk)
	VMBusLoaded   bool `json:"vmbus_loaded"`   // hv_vmbus (the VMBus transport)

	// --- Azure Linux Agent (waagent) ---
	WAAgentInstalled bool `json:"waagent_installed"`
	WAAgentRunning   bool `json:"waagent_running"`

	// --- Hyper-V PTP time source ---
	TimeSyncChecked bool `json:"time_sync_checked"`
	UsesHyperVPTP   bool `json:"uses_hyperv_ptp"` // chrony/timesyncd on /dev/ptp_hyperv (PHC refclock)
}

// ANIface is the state of one Accelerated-Networking SR-IOV VF. Bonded is true when
// the VF is enslaved under a synthetic hv_netvsc NIC (Azure's transparent-bonding
// model); Up reflects its operstate. A VF that exists but is not bonded or not up
// means the accelerated datapath is not actually carrying traffic.
type ANIface struct {
	VF        string `json:"vf"`                  // VF interface name (e.g. "enP1s2")
	Driver    string `json:"driver"`              // mlx5_core / mlx4_en / mana
	Synthetic string `json:"synthetic,omitempty"` // the hv_netvsc NIC it is bonded under, if any
	Bonded    bool   `json:"bonded"`              // enslaved under a synthetic NIC (transparent bonding)
	Up        bool   `json:"up"`                  // operstate == up
}
