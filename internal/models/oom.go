package models

import "time"

// OOMEvent is one OOM kill record parsed from the kernel log.
type OOMEvent struct {
	Process   string    `json:"process"`
	PID       int       `json:"pid,omitempty"`
	Timestamp time.Time `json:"timestamp,omitempty"`
	Reason    string    `json:"reason,omitempty"` // raw kernel line summary
}

// OOMInfo holds OOM killer activity parsed from journal/dmesg.
type OOMInfo struct {
	Available     bool       `json:"available"`
	EventsLast24h int        `json:"events_last_24h"`
	RecentEvents  []OOMEvent `json:"recent_events,omitempty"` // up to 5 most recent
	Status        string     `json:"status,omitempty"`
	StatusReason  string     `json:"status_reason,omitempty"`
}
