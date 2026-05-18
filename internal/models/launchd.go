package models

// LaunchdService is one service managed by launchd on macOS.
type LaunchdService struct {
	Label  string `json:"label"`
	PID    int    `json:"pid,omitempty"`    // 0 = not running
	Status int    `json:"status,omitempty"` // last exit code; 0 = clean
}

// LaunchdInfo holds macOS launchd service health.
type LaunchdInfo struct {
	Total        int              `json:"total"`
	Running      int              `json:"running"`
	Failed       []LaunchdService `json:"failed,omitempty"` // exited non-zero, not running
	Status       string           `json:"status,omitempty"`
	StatusReason string           `json:"status_reason,omitempty"`
}
