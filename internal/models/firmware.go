package models

// FirmwareUpgrade holds info about a pending firmware update for one device.
type FirmwareUpgrade struct {
	Name        string `json:"name"`
	Summary     string `json:"summary,omitempty"`
	CurrentVer  string `json:"current_version,omitempty"`
	NewVer      string `json:"new_version,omitempty"`
	NeedsReboot bool   `json:"needs_reboot,omitempty"`
	SecurityFix bool   `json:"security_fix,omitempty"` // dbx, BIOS security patches
}

// FirmwareInfo holds firmware update state from fwupd.
type FirmwareInfo struct {
	Available     bool              `json:"available"` // fwupd installed
	Upgrades      []FirmwareUpgrade `json:"upgrades,omitempty"`
	UpgradeCount  int               `json:"upgrade_count"`
	SecurityCount int               `json:"security_count"` // security-relevant upgrades
	Status        string            `json:"status,omitempty"`
	StatusReason  string            `json:"status_reason,omitempty"`
}
