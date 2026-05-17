package models

// ISCSISession is one active iSCSI session.
type ISCSISession struct {
	Target string `json:"target"`
	Portal string `json:"portal"`
	State  string `json:"state"`            // LOGGED_IN, FAILED
	Device string `json:"device,omitempty"` // /dev/sdX
}

// ISCSIInfo holds iSCSI initiator session health.
type ISCSIInfo struct {
	Available    bool           `json:"available"`
	Sessions     []ISCSISession `json:"sessions,omitempty"`
	FailedCount  int            `json:"failed_count,omitempty"`
	Status       string         `json:"status,omitempty"`
	StatusReason string         `json:"status_reason,omitempty"`
}
