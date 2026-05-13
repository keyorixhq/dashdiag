package models

// HardwareDrive holds SMART health for a single drive (NVMe or SATA/SAS).
// Populated from smartctl --json output — unified across drive types.
type HardwareDrive struct {
	Device   string `json:"device"`     // /dev/sda, /dev/nvme0
	Model    string `json:"model"`      // drive model string
	Type     string `json:"type"`       // nvme, sata, sas
	SmartOK  bool   `json:"smart_ok"`   // overall SMART self-assessment passed
	TempC    int    `json:"temp_c"`     // current temperature in °C
	PowerOnH int64  `json:"power_on_h"` // total power-on hours

	// Wear / endurance
	WearPct int `json:"wear_pct"` // % of rated endurance consumed (NVMe: percentage_used; SATA SSD: 100 - remaining_life)

	// Error counters
	MediaErrors         int64 `json:"media_errors"`         // NVMe media/data integrity errors
	UnsafeShutdowns     int64 `json:"unsafe_shutdowns"`     // NVMe unsafe shutdown count
	ReallocatedSectors  int   `json:"reallocated_sectors"`  // SATA attr 5 — sectors remapped due to errors
	PendingSectors      int   `json:"pending_sectors"`      // SATA attr 197 — sectors waiting for remap
	UncorrectableErrors int   `json:"uncorrectable_errors"` // SATA attr 198 — offline uncorrectable

	// Availability
	SmartctlAvailable bool   `json:"smartctl_available"` // false if smartctl not installed
	Error             string `json:"error,omitempty"`
}

// HardwareThermal holds a single hwmon temperature reading.
type HardwareThermal struct {
	Sensor string `json:"sensor"` // k10temp, coretemp, nvme
	Label  string `json:"label"`  // Tctl, Core 0, Composite
	TempC  int    `json:"temp_c"`
}

// HardwareMemory holds EDAC memory error counts.
type HardwareMemory struct {
	EDACAvailable     bool  `json:"edac_available"`
	UncorrectedErrors int64 `json:"uncorrected_errors"` // ue_count — hardware fault
	CorrectedErrors   int64 `json:"corrected_errors"`   // ce_count — soft error, self-corrected
}

// HardwareInfo is the top-level model returned by HardwareCollector.
type HardwareInfo struct {
	Drives   []HardwareDrive   `json:"drives"`
	Thermals []HardwareThermal `json:"thermals,omitempty"`
	Memory   HardwareMemory    `json:"memory"`
}
