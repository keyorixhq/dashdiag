package models

// GPUProcess holds info about a process using the GPU.
type GPUProcess struct {
	PID      int    `json:"pid"`
	Name     string `json:"name"`
	MemUseMB int    `json:"mem_use_mb"`
}

// GPUDevice holds health data for a single GPU.
type GPUDevice struct {
	Index      int          `json:"index"`
	Name       string       `json:"name"`
	TempC      int          `json:"temp_c"`
	UtilPct    int          `json:"util_pct"`
	MemUsedMB  int          `json:"mem_used_mb"`
	MemTotalMB int          `json:"mem_total_mb"`
	MemUsedPct float64      `json:"mem_used_pct"`
	PowerDrawW float64      `json:"power_draw_w"`
	XidErrors  int          `json:"xid_errors"`
	Processes  []GPUProcess `json:"processes,omitempty"`
}

// GPUInfo holds data for all GPUs on the system.
type GPUInfo struct {
	Devices       []GPUDevice `json:"devices"`
	DriverVersion string      `json:"driver_version,omitempty"`
	Status        string      `json:"status,omitempty"`
	StatusReason  string      `json:"status_reason,omitempty"`
}
