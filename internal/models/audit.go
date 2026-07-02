package models

// AuditInfo holds auditd health and recent event summary.
type AuditInfo struct {
	Available      bool    `json:"available"`
	Running        bool    `json:"running"`
	RulesLoaded    int     `json:"rules_loaded,omitempty"`
	EventsLast1h   int     `json:"events_last_1h,omitempty"`
	AuditLogSizeGB float64 `json:"audit_log_size_gb,omitempty"`
	// AuditLogSizeUnreadable is true when /var/log/audit/audit.log exists but
	// could not be stat'd (the 0700 root:root audit dir denies non-root) —
	// distinct from a genuinely small log. Without it, a non-root run can't
	// tell "log is small" from "couldn't read it", so a host with a runaway
	// multi-GB audit log reads healthy unprivileged while root would WARN.
	AuditLogSizeUnreadable bool   `json:"audit_log_size_unreadable,omitempty"`
	Status                 string `json:"status,omitempty"`
	StatusReason           string `json:"status_reason,omitempty"`
}
