package models

type ClockInfo struct {
	Synced       bool    `json:"synced"`
	OffsetMs     float64 `json:"offset_ms"`
	Source       string  `json:"source"`
	Status       string  `json:"status"`
	StatusReason string  `json:"status_reason"`
}
