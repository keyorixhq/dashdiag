package models

import "time"

// OOMEvent is one OOM kill record parsed from the kernel log.
type OOMEvent struct {
	Process   string    `json:"process"`
	PID       int       `json:"pid,omitempty"`
	Timestamp time.Time `json:"timestamp,omitzero"`
	Reason    string    `json:"reason,omitempty"` // raw kernel line summary
}

// OOMInfo holds OOM killer activity parsed from journal/dmesg.
type OOMInfo struct {
	Available     bool       `json:"available"`
	EventsLast24h int        `json:"events_last_24h"`
	RecentEvents  []OOMEvent `json:"recent_events,omitempty"` // up to 5 most recent
	// EventsCountUnverified is true when the kernel log scan stopped early on
	// a scan error (e.g. a line past the ~64KB default buffer) — EventsLast24h
	// is then a partial count, not a verified total; any OOM events on lines
	// after the failure point are missing from it.
	EventsCountUnverified bool   `json:"events_count_unverified,omitempty"`
	Status                string `json:"status,omitempty"`
	StatusReason          string `json:"status_reason,omitempty"`
}
