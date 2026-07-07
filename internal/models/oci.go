package models

// OCIInfo reports guest-side health for a Linux instance on Oracle Cloud
// Infrastructure (OCI) — the OCI-specific signals a guest can see about itself
// that the generic collectors miss. Populated only when running on OCI (gate:
// DMI chassis_asset_tag "OracleCloud.com"); nil/zero everywhere else so it adds
// no noise off OCI.
//
// Scope is strictly guest-side, no OCI API credentials: instance metadata
// (IMDS v2 posture), local daemon state (oracle-cloud-agent), NTP configuration
// against OCI's metadata NTP server, and VNIC ring-buffer drop counters. Block
// volume iSCSI session health is deliberately NOT duplicated here — the generic
// ISCSICollector already covers it for every host, OCI included.
type OCIInfo struct {
	IsOCI              bool   `json:"is_oci"`
	Shape              string `json:"shape,omitempty"`               // e.g. "VM.Standard.A1.Flex"
	Region             string `json:"region,omitempty"`              // canonical region name, e.g. "us-phoenix-1"
	AvailabilityDomain string `json:"availability_domain,omitempty"` // e.g. "Bdcu:PHX-AD-1"

	// --- IMDS security posture ---
	// OCI's IMDS v2 requires "Authorization: Bearer Oracle" on every request. A
	// request WITHOUT that header succeeding means legacy/unauthenticated access
	// is still reachable — the same SSRF-exposure class as AWS's IMDSv1-open
	// finding. IMDSChecked is false when IMDS itself was unreachable, so we
	// never imply a posture we couldn't read.
	IMDSChecked bool `json:"imds_checked"`
	IMDSv1Open  bool `json:"imds_v1_open,omitempty"`

	// --- oracle-cloud-agent (OCI's guest agent: Compute Instance Run Command,
	// monitoring, and OS Management Hub plugins all depend on it) ---
	AgentChecked        bool `json:"agent_checked"`
	AgentInstalled      bool `json:"agent_installed"`
	AgentRunning        bool `json:"agent_running"`
	AgentUpdaterRunning bool `json:"agent_updater_running"`

	// --- time sync against OCI's metadata NTP server (169.254.169.254) ---
	TimeSyncChecked bool `json:"time_sync_checked"`
	UsesOCITimeSync bool `json:"uses_oci_time_sync,omitempty"`
	TimeSynced      bool `json:"time_synced,omitempty"` // configured AND actively selected/synced, not just present in config

	// --- VNIC ring health ---
	// virtio_net (OCI's standard paravirtualized VNIC driver) exposes ring-buffer
	// drop/timeout counters via `ethtool -S` that the generic
	// /sys/class/net/*/statistics/rx_errors counters do not catch — real packet
	// loss at the driver level can hide behind a clean generic NIC-error check.
	VNICChecked bool      `json:"vnic_checked"`
	VNICs       []OCIVNIC `json:"vnics,omitempty"`
}

// OCIVNIC holds ring-buffer drop/timeout counters for one virtio_net interface.
type OCIVNIC struct {
	Iface      string `json:"iface"`
	Driver     string `json:"driver"`
	RxDrops    uint64 `json:"rx_drops"`
	TxTimeouts uint64 `json:"tx_timeouts"`
}
