package models

// AzureInfo reports guest-side health for a Linux VM on Microsoft Azure — the
// Azure-specific signals a guest can see about itself that the generic collectors
// miss. Populated only on Azure (gate: DMI chassis asset tag); nil/zero everywhere
// else so it adds no noise off Azure.
//
// Scope is strictly guest-side, no authenticated Azure API: kernel/driver topology
// (the Hyper-V synthetic NICs + Accelerated-Networking SR-IOV VFs), local daemon
// state (the Azure Linux agent, the Hyper-V PTP time source), the Dynamic-Memory
// balloon driver, the resource (temp) disk, and host-cache settings read from the
// unauthenticated link-local Instance Metadata Service (IMDS, 169.254.169.254). The
// headline failure it targets is the Accelerated-Networking false-green: AN shows
// "enabled" in the portal but the VF never attached, so traffic silently rides the
// slow synthetic path.
//
// Unlike AWS EBS, Azure exposes no guest-side disk-throttle telemetry (managed disks
// are SCSI via hv_storvsc, with no vendor log page), so there is deliberately no
// disk-throttle field here — that signal lives only in the Azure API/metrics. Host
// *cache mode* (below) is config, not telemetry, and IS readable from IMDS.
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

	// --- Dynamic Memory (Hyper-V ballooning) ---
	// hv_balloon loaded == the VM was provisioned with Dynamic Memory. Recognition
	// context only: the driver's presence is a confident guest-side fact; ballooning
	// *pressure* has no reliable guest-side counter, so it is deliberately not claimed
	// here (would be a false signal). DynMemMaxMB carries the configured ceiling when
	// the kernel logged it ("hv_balloon: Max. dynamic memory size: N MB"), else 0.
	DynamicMemory bool `json:"dynamic_memory"`
	DynMemMaxMB   int  `json:"dyn_mem_max_mb,omitempty"`

	// --- Resource (temp) disk ---
	// Azure's local temp/resource disk is ephemeral: its contents are lost on
	// deallocation or host migration. TempDiskDevice is the WAAgent-managed
	// /dev/disk/azure/resource target when present (the definitive marker).
	// PersistentDataAtRisk is set when /etc/fstab mounts non-ephemeral-looking data
	// onto the temp mount — the classic "I lost my data" footgun.
	TempDiskPresent      bool   `json:"temp_disk_present"`
	TempDiskDevice       string `json:"temp_disk_device,omitempty"`
	TempDiskMount        string `json:"temp_disk_mount,omitempty"`
	PersistentDataAtRisk bool   `json:"temp_disk_persistent_data_at_risk,omitempty"`

	// --- Managed-disk host caching (from IMDS storageProfile) ---
	// DisksChecked is false when IMDS could not be read, so an unread storage profile
	// never reads as "no caching problems" (couldn't-measure, not OK).
	DisksChecked bool        `json:"disks_checked"`
	Disks        []AzureDisk `json:"disks,omitempty"`

	// --- NVMe I/O timeout (full-coverage tail) ---
	// Azure v5+ VMs surface managed/local disks as NVMe; the kernel default
	// nvme_core.io_timeout (30s) can turn a transient managed-disk latency spike into
	// an I/O error, so Azure recommends raising it (commonly 240s). Checked only when
	// NVMe is present; NVMeIOTimeoutChecked is false otherwise so a non-NVMe VM stays
	// silent rather than reading as OK.
	NVMePresent          bool `json:"nvme_present"`
	NVMeIOTimeoutChecked bool `json:"nvme_io_timeout_checked"`
	NVMeIOTimeoutSecs    int  `json:"nvme_io_timeout_secs,omitempty"`
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

// AzureDisk is one disk's host-cache setting as reported by the IMDS storageProfile.
// Caching is the Azure host-side cache mode ("None"/"ReadOnly"/"ReadWrite"); it is a
// control-plane setting, not guest telemetry, but IMDS exposes it to the guest. IsOS
// distinguishes the OS disk (ReadWrite is the safe default there) from data disks
// (where ReadWrite host caching is the documented hazard for write-heavy/DB volumes).
type AzureDisk struct {
	Name    string `json:"name,omitempty"`
	IsOS    bool   `json:"is_os"`
	Lun     int    `json:"lun,omitempty"`     // data-disk LUN (osDisk has none)
	Caching string `json:"caching,omitempty"` // None / ReadOnly / ReadWrite
}
