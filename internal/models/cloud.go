package models

// CloudInfo holds cloud instance metadata and health signals.
type CloudInfo struct {
	Available          bool   `json:"available"`
	Provider           string `json:"provider"` // aws, azure, gcp, unknown
	InstanceID         string `json:"instance_id"`
	InstanceType       string `json:"instance_type"`
	Region             string `json:"region"`
	SpotTermination    bool   `json:"spot_termination"`  // spot/preemptible termination notice
	MaintenanceEvent   bool   `json:"maintenance_event"` // scheduled maintenance
	MaintenanceDetails string `json:"maintenance_details,omitempty"`
	Status             string `json:"status,omitempty"`
	StatusReason       string `json:"status_reason,omitempty"`
}
