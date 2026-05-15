package models

type ClockInfo struct {
	Synced       bool    `json:"synced"`
	OffsetMs     float64 `json:"offset_ms"`
	Source       string  `json:"source"`
	Status       string  `json:"status"`
	StatusReason string  `json:"status_reason"`
	RTCInLocalTZ bool    `json:"rtc_in_local_tz,omitempty"` // true if RTC set to local time — causes kernel sync issues
}
