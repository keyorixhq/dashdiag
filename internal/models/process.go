package models

type ProcessState struct {
	PID        int     `json:"pid"`
	PPID       int     `json:"ppid"`
	Name       string  `json:"name"`
	ParentName string  `json:"parent_name,omitempty"`
	State      string  `json:"state"`
	CPU        float64 `json:"cpu"`
	MemMB      float64 `json:"mem_mb"`
	WChan      string  `json:"wchan,omitempty"`
}

type ProcessInfo struct {
	Total        int            `json:"total"` // total running processes
	ZombieCount  int            `json:"zombie_count"`
	HungCount    int            `json:"hung_count"`
	ZombieProcs  []ProcessState `json:"zombie_procs"`
	HungProcs    []ProcessState `json:"hung_procs"`
	Status       string         `json:"status"`
	StatusReason string         `json:"status_reason"`
	// ListRestricted is true when the /proc listing hides other users' processes
	// (hidepid=1/2, systemd ProtectProc=invisible): PID 1 is absent from it, so
	// Total/ZombieCount/HungCount cover only what this UID could see, not the host.
	ListRestricted bool `json:"list_restricted,omitempty"`
	// ListUnreadable is true when the process table could not be listed at all
	// (macOS `ps` failed), so zero counts mean "not measured", not "none".
	ListUnreadable bool `json:"list_unreadable,omitempty"`
}
