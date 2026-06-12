package models

// HardwareDrive holds SMART health for a single drive (NVMe or SATA/SAS).
type HardwareDrive struct {
	Device string `json:"device"`
	Model  string `json:"model"`
	Type   string `json:"type"`
	// SmartRead is true only when smartctl actually reported a SMART verdict
	// (smart_status present). False = detected but unread (controller/USB bridge
	// /virtual disk) — must not fire a "drive may fail imminently" CRIT.
	SmartRead           bool   `json:"smart_read"`
	SmartOK             bool   `json:"smart_ok"`
	TempC               int    `json:"temp_c"`
	PowerOnH            int64  `json:"power_on_h"`
	WearPct             int    `json:"wear_pct"`
	MediaErrors         int64  `json:"media_errors"`
	UnsafeShutdowns     int64  `json:"unsafe_shutdowns"`
	ReallocatedSectors  int    `json:"reallocated_sectors"`
	PendingSectors      int    `json:"pending_sectors"`
	UncorrectableErrors int    `json:"uncorrectable_errors"`
	SmartctlAvailable   bool   `json:"smartctl_available"`
	Error               string `json:"error,omitempty"`
}

// HardwareThermal holds a single hwmon temperature reading.
type HardwareThermal struct {
	Sensor string `json:"sensor"`
	Label  string `json:"label"`
	TempC  int    `json:"temp_c"`
}

// MemorySlot holds info about a single RAM slot from dmidecode.
type MemorySlot struct {
	Locator string  `json:"locator"`
	SizeGB  float64 `json:"size_gb"`
	Type    string  `json:"type"`
	SpeedMT int     `json:"speed_mt"` // MT/s
}

// HardwareMemory holds EDAC error counts and RAM slot info.
type HardwareMemory struct {
	EDACAvailable     bool         `json:"edac_available"`
	UncorrectedErrors int64        `json:"uncorrected_errors"`
	CorrectedErrors   int64        `json:"corrected_errors"`
	TotalGB           float64      `json:"total_gb"`
	Slots             []MemorySlot `json:"slots,omitempty"`
}

// HardwareCPU holds CPU info from /proc/cpuinfo and cpufreq sysfs.
type HardwareCPU struct {
	Model      string  `json:"model"`
	Cores      int     `json:"cores"`
	Threads    int     `json:"threads"`
	FreqMHz    float64 `json:"freq_mhz"`     // current frequency
	MaxFreqMHz float64 `json:"max_freq_mhz"` // max boost frequency
	LoadPct    float64 `json:"load_pct"`     // 1-min load avg as % of CPU capacity
}

// HardwareNIC holds network interface hardware info.
type HardwareNIC struct {
	Name      string `json:"name"`
	MAC       string `json:"mac"`
	SpeedMbps int    `json:"speed_mbps"`
	State     string `json:"state"`
	RxErrors  int64  `json:"rx_errors"`
	TxErrors  int64  `json:"tx_errors"`
	Driver    string `json:"driver,omitempty"`
}

// HardwareSystem holds system identity from DMI/sysfs.
type HardwareSystem struct {
	Vendor string `json:"vendor"`
	Model  string `json:"model"`
	Board  string `json:"board,omitempty"`
}

// HardwareInfo is the top-level model returned by HardwareCollector.
type HardwareInfo struct {
	System   HardwareSystem    `json:"system"`
	CPU      HardwareCPU       `json:"cpu"`
	Drives   []HardwareDrive   `json:"drives"`
	Thermals []HardwareThermal `json:"thermals,omitempty"`
	Memory   HardwareMemory    `json:"memory"`
	NICs     []HardwareNIC     `json:"nics,omitempty"`
}
