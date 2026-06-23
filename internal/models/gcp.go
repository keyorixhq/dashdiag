package models

// GCPInfo reports guest-side health for a Linux VM on Google Compute Engine — the
// GCP-specific signals a guest can see about itself, the analog of AWSInfo/AzureInfo.
// Populated only on GCE (gate: DMI product_name "Google Compute Engine"); nil/zero
// everywhere else so it adds no noise off GCP.
//
// Scope is strictly guest-side, no authenticated GCP API: NIC driver topology, the
// Google guest agent service, and config/metadata read from the unauthenticated
// link-local metadata server (metadata.google.internal / 169.254.169.254, which
// requires the "Metadata-Flavor: Google" header). The headline failures it targets are
// the guest-agent-down case (SSH-key / OS-Login propagation silently breaks) and a
// host-maintenance policy of TERMINATE on a VM the operator assumed would live-migrate.
type GCPInfo struct {
	IsGCP bool `json:"is_gcp"`

	// --- NIC driver (recognition/context) ---
	// gVNIC (gve) is the modern high-bandwidth virtual NIC and a prerequisite for
	// Tier_1 networking; virtio_net is the older default and works fine — so this is
	// context, not a fault.
	NICDriver string `json:"nic_driver,omitempty"` // primary NIC driver: gve / virtio_net
	UsesGVNIC bool   `json:"uses_gvnic"`           // at least one gve interface present

	// --- Google guest agent ---
	GuestAgentInstalled bool `json:"guest_agent_installed"`
	GuestAgentRunning   bool `json:"guest_agent_running"`

	// --- Host-maintenance behaviour (from the metadata server) ---
	// MaintenanceChecked is false when the metadata server could not be read, so an
	// unread policy never reads as "fine". OnHostMaintenance is MIGRATE (live-migrate,
	// the safe default) or TERMINATE (the VM stops on host maintenance — a risk on a
	// non-preemptible VM the operator expected to survive). ActiveMaintenance carries a
	// non-NONE maintenance-event value when one is in progress.
	MaintenanceChecked bool   `json:"maintenance_checked"`
	OnHostMaintenance  string `json:"on_host_maintenance,omitempty"` // MIGRATE / TERMINATE
	ActiveMaintenance  string `json:"active_maintenance,omitempty"`  // e.g. MIGRATE_ON_HOST_MAINTENANCE
	Preemptible        bool   `json:"preemptible"`                   // TERMINATE is expected on preemptible VMs

	// --- OS Login (recognition/context) ---
	OSLoginChecked bool `json:"os_login_checked"`
	OSLoginEnabled bool `json:"os_login_enabled"`

	// --- Time sync ---
	// GCP recommends the metadata server (metadata.google.internal / 169.254.169.254)
	// as the NTP source. TimeSyncChecked is false when no chrony/timesyncd config was
	// found, so we never claim a verdict on time config we couldn't see.
	TimeSyncChecked bool `json:"time_sync_checked"`
	UsesMetadataNTP bool `json:"uses_metadata_ntp"`
}
