package models

// CloudInitInfo captures the state of cloud-init on a provisioned instance.
// Populated from `cloud-init status --format=json`. Generic to every cloud-init
// platform (AWS/GCP/Oracle/OpenStack + any cloud-init-provisioned VM), not
// cloud-provider-specific — the point is catching "booted but never finished
// configuring" regardless of where the box runs.
type CloudInitInfo struct {
	Available bool `json:"available"`
	// Status is the raw `status` field: "done" | "running" | "error" |
	// "disabled" | "not run".
	Status string `json:"status"`
	// ExtendedStatus is the richer state on cloud-init >= 23.x, e.g.
	// "degraded done" (completed but with recoverable errors). Empty on older.
	ExtendedStatus string `json:"extended_status,omitempty"`
	// BootStatusCode e.g. "enabled-by-generator", "disabled-by-marker-file".
	BootStatusCode string `json:"boot_status_code,omitempty"`
	// Datasource e.g. "nocloud", "ec2", "gce", "openstack".
	Datasource string `json:"datasource,omitempty"`
	// Errors holds fatal error strings (the `errors` array).
	Errors []string `json:"errors,omitempty"`
	// RecoverableErrors flattens the `recoverable_errors` map (level → []msg).
	RecoverableErrors []string `json:"recoverable_errors,omitempty"`
	LastUpdate        string   `json:"last_update,omitempty"`
}
