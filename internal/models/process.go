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
}
