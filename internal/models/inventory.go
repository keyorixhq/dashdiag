package models

// Inventory is a CMDB-ingestable snapshot of a host's technical facts —
// hardware identity, specs, and installed-software summary. It is assembled
// from data DashDiag already collects during diagnosis (HardwareInfo + the
// platform Profile) plus a few cheap identity reads; nothing new is probed.
//
// Scope note: this is the *technical-facts* layer only (model/serial/specs).
// It deliberately does NOT carry the administrative layer (owner, asset tag,
// purchase/warranty date, location, licences) — none of that is visible from
// the box. A CMDB sources the admin layer elsewhere; this populates the rest.
type Inventory struct {
	CollectedAt string `json:"collected_at"`
	Tool        string `json:"tool"`
	ToolVersion string `json:"tool_version"`

	Host     InventoryHost     `json:"host"`
	System   InventorySystem   `json:"system"`
	CPU      InventoryCPU      `json:"cpu"`
	Memory   InventoryMemory   `json:"memory"`
	Drives   []InventoryDrive  `json:"drives,omitempty"`
	NICs     []InventoryNIC    `json:"nics,omitempty"`
	Software InventorySoftware `json:"software"`
}

type InventoryHost struct {
	Hostname      string `json:"hostname"`
	OS            string `json:"os"`             // PRETTY_NAME, e.g. "Ubuntu 24.04 LTS"
	Distro        string `json:"distro"`         // normalized id, e.g. "ubuntu"
	DistroVersion string `json:"distro_version"` // e.g. "24.04"
	Kernel        string `json:"kernel"`         // uname -r
	Arch          string `json:"arch"`           // GOARCH: amd64, arm64
	MachineID     string `json:"machine_id,omitempty"`
}

type InventorySystem struct {
	Vendor string `json:"vendor,omitempty"`
	Model  string `json:"model,omitempty"`
	Board  string `json:"board,omitempty"`
	Serial string `json:"serial,omitempty"` // DMI product_serial (often root-only)
}

type InventoryCPU struct {
	Model   string `json:"model,omitempty"`
	Cores   int    `json:"cores,omitempty"`
	Threads int    `json:"threads,omitempty"`
}

type InventoryMemory struct {
	TotalGB float64         `json:"total_gb,omitempty"`
	Slots   []InventorySlot `json:"slots,omitempty"`
}

type InventorySlot struct {
	Locator string  `json:"locator"`
	SizeGB  float64 `json:"size_gb"`
	Type    string  `json:"type,omitempty"`
	SpeedMT int     `json:"speed_mt,omitempty"`
}

type InventoryDrive struct {
	Device string  `json:"device"`
	Model  string  `json:"model,omitempty"`
	Serial string  `json:"serial,omitempty"`
	SizeGB float64 `json:"size_gb,omitempty"`
}

type InventoryNIC struct {
	Name      string `json:"name"`
	MAC       string `json:"mac,omitempty"`
	SpeedMbps int    `json:"speed_mbps,omitempty"`
	Driver    string `json:"driver,omitempty"`
}

type InventorySoftware struct {
	PackageManager string `json:"package_manager,omitempty"`
	PackageCount   int    `json:"package_count,omitempty"`
}
