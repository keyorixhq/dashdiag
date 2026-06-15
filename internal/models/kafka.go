package models

// KafkaInfo holds guest-side health for a local Kafka broker. Gated on the broker
// port (9092) being up with a kafka CLI present. The headline signal is OFFLINE
// partitions: a partition with no leader can neither be produced to nor consumed
// from — its data is unavailable, a live outage. Under-replicated partitions are
// the softer signal (replicas not in sync → no redundancy). Reading topic metadata
// needs the CLI to reach the bootstrap server; when it can't (SSL/SASL auth, or the
// broker is mid-startup), MetricsRead stays false — never a false green.
type KafkaInfo struct {
	Detected  bool `json:"detected"`
	Accepting bool `json:"accepting"` // broker port (9092) reachable

	MetricsRead bool `json:"metrics_read"`
	// UnderReplicatedRead is true only when the under-replicated-partitions query
	// actually returned. MetricsRead covers the offline-partition read; without a
	// separate flag a failed URP query left the count at 0 and redundancy read as
	// verified-healthy when it was never checked.
	UnderReplicatedRead       bool   `json:"under_replicated_read,omitempty"`
	OfflinePartitions         int    `json:"offline_partitions,omitempty"`
	UnderReplicatedPartitions int    `json:"under_replicated_partitions,omitempty"`
	OfflineDetail             string `json:"offline_detail,omitempty"`
	URPDetail                 string `json:"urp_detail,omitempty"`

	StatusReason string `json:"status_reason,omitempty"`
}
