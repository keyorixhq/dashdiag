package models

// LaunchdService is one service managed by launchd on macOS.
type LaunchdService struct {
	Label  string `json:"label"`
	PID    int    `json:"pid,omitempty"`    // 0 = not running
	Status int    `json:"status,omitempty"` // last exit code; 0 = clean
}

// LaunchdInfo holds macOS launchd service health.
type LaunchdInfo struct {
	Total   int              `json:"total"`
	Running int              `json:"running"`
	Failed  []LaunchdService `json:"failed,omitempty"` // exited non-zero, not running
	// Checked is true only when `launchctl list` actually ran and its output was
	// parsed. False on any run failure — distinct from a genuinely healthy host
	// with zero failed services, which also leaves Failed empty. Without this, a
	// broken/inaccessible launchd renders as "checked every service, zero
	// failures" instead of "could not check".
	Checked      bool   `json:"checked"`
	Status       string `json:"status,omitempty"`
	StatusReason string `json:"status_reason,omitempty"`
}
