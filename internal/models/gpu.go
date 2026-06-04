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
	Vendor     string       `json:"vendor,omitempty"` // "nvidia", "amd", "intel"
	TempC      int          `json:"temp_c"`
	UtilPct    int          `json:"util_pct"`
	MemUsedMB  int          `json:"mem_used_mb"`
	MemTotalMB int          `json:"mem_total_mb"`
	MemUsedPct float64      `json:"mem_used_pct"`
	PowerDrawW float64      `json:"power_draw_w"`
	XidErrors  int          `json:"xid_errors"`
	Processes  []GPUProcess `json:"processes,omitempty"`

	// Clock speeds
	ClockMHz    int `json:"clock_mhz,omitempty"`     // current GPU core clock
	ClockMaxMHz int `json:"clock_max_mhz,omitempty"` // max available clock

	// Power / TDP (more precise than PowerDrawW — that stays for NVIDIA compat).
	// For AMD, PowerDrawW is also set to TDPCurrentW so existing heuristics work.
	TDPLimitW   float64 `json:"tdp_limit_w,omitempty"`   // configured TDP cap
	TDPMaxW     float64 `json:"tdp_max_w,omitempty"`     // hardware max
	TDPCurrentW float64 `json:"tdp_current_w,omitempty"` // current draw (AMD power1_input)
	Throttling  bool    `json:"throttling,omitempty"`    // draw >= 95% of cap

	// VRAM in GB (complement to MemUsedMB/MemTotalMB — GB is cleaner for display)
	VRAMUsedGB  float64 `json:"vram_used_gb,omitempty"`
	VRAMTotalGB float64 `json:"vram_total_gb,omitempty"`
	VRAMUsedPct float64 `json:"vram_used_pct,omitempty"`
	IsAPU       bool    `json:"is_apu,omitempty"` // shared system RAM (Steam Deck)

	// Thermal extras
	TempJunctionC int `json:"temp_junction_c,omitempty"` // hotspot / die temp
	TempMemC      int `json:"temp_mem_c,omitempty"`      // GDDR temp

	// Memory bus utilization
	MemBusyPct int `json:"mem_busy_pct,omitempty"`

	// Driver / Mesa
	MesaVersion string `json:"mesa_version,omitempty"` // e.g. "24.3.1"
	DRMDriver   string `json:"drm_driver,omitempty"`   // "amdgpu", "i915", "nouveau"

	// Deep-only
	PowerDPMLevel string `json:"power_dpm_level,omitempty"` // "auto", "low", "high"
}

// GPUDetected is a GPU found in sysfs but with no driver loaded.
type GPUDetected struct {
	Name    string `json:"name"`
	Vendor  string `json:"vendor"` // "nvidia", "amd", "intel"
	PCIAddr string `json:"pci_addr,omitempty"`
}

// GPUInfo holds data for all GPUs on the system.
type GPUInfo struct {
	Devices       []GPUDevice   `json:"devices"`
	NoDriver      []GPUDetected `json:"no_driver,omitempty"` // GPUs found but driver not loaded
	DriverVersion string        `json:"driver_version,omitempty"`
	Status        string        `json:"status,omitempty"`
	StatusReason  string        `json:"status_reason,omitempty"`
}
