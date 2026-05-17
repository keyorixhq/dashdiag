package models

// PSILine holds one line of PSI (Pressure Stall Information) metrics.
// Files: /sys/fs/cgroup/memory.pressure, cpu.pressure, io.pressure
// Format: "some avg10=X.XX avg60=X.XX avg300=X.XX total=N"
type PSILine struct {
	Avg10  float64 `json:"avg10"`  // % stall in last 10s
	Avg60  float64 `json:"avg60"`  // % stall in last 60s
	Avg300 float64 `json:"avg300"` // % stall in last 300s
}

// PressureInfo holds PSI pressure stall data for memory, CPU, and IO.
// Only available on Linux kernels 4.20+ with cgroup v2.
type PressureInfo struct {
	Available    bool    `json:"available"`
	MemorySome   PSILine `json:"memory_some"` // at least one task stalled
	MemoryFull   PSILine `json:"memory_full"` // all tasks stalled (more severe)
	CPUSome      PSILine `json:"cpu_some"`
	IOSome       PSILine `json:"io_some"`
	IOFull       PSILine `json:"io_full"`
	Status       string  `json:"status,omitempty"`
	StatusReason string  `json:"status_reason,omitempty"`
}
