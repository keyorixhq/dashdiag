package models

// PackageUpdate represents a single available security update.
type PackageUpdate struct {
	Name     string `json:"name"`
	Severity string `json:"severity"` // Critical, Important, Moderate, Low
	Advisory string `json:"advisory"` // e.g. RHSA-2026:1234
}

// PackagesInfo holds package security advisory data.
type PackagesInfo struct {
	SecurityUpdates  int             `json:"security_updates"`
	CriticalUpdates  int             `json:"critical_updates"`
	ImportantUpdates int             `json:"important_updates"`
	Updates          []PackageUpdate `json:"updates,omitempty"`
	PackageManager   string          `json:"package_manager"` // dnf, apt, brew
	Status           string          `json:"status,omitempty"`
	StatusReason     string          `json:"status_reason,omitempty"`
}
