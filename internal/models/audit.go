package models

// AuditInfo holds auditd health and recent event summary.
type AuditInfo struct {
	Available      bool    `json:"available"`
	Running        bool    `json:"running"`
	RulesLoaded    int     `json:"rules_loaded,omitempty"`
	EventsLast1h   int     `json:"events_last_1h,omitempty"`
	AuditLogSizeGB float64 `json:"audit_log_size_gb,omitempty"`
	Status         string  `json:"status,omitempty"`
	StatusReason   string  `json:"status_reason,omitempty"`
}
