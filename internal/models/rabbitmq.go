package models

// RabbitMQInfo holds guest-side health for a local RabbitMQ broker. Gated on the
// AMQP port being up with the rabbitmq CLI present. The headline signal is a
// resource alarm: when RabbitMQ crosses its memory or disk watermark it BLOCKS
// all publishers — messages silently stop being accepted — so an active alarm is
// a live outage. Metric depth needs the Erlang cookie (root / the rabbitmq user);
// when diagnostics can't run, DiagnosticsRead stays false (never a false green).
type RabbitMQInfo struct {
	Detected  bool   `json:"detected"`
	Version   string `json:"version,omitempty"`
	Accepting bool   `json:"accepting"` // AMQP port (5672) reachable

	DiagnosticsRead bool   `json:"diagnostics_read"`
	Pinged          bool   `json:"pinged,omitempty"`
	MemoryAlarm     bool   `json:"memory_alarm,omitempty"`
	DiskAlarm       bool   `json:"disk_alarm,omitempty"`
	AlarmDetail     string `json:"alarm_detail,omitempty"`

	StatusReason string `json:"status_reason,omitempty"`
}
