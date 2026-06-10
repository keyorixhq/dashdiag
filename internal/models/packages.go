package models

// PackageUpdate represents a single available security update.
type PackageUpdate struct {
	Name     string `json:"name"`
	Severity string `json:"severity"` // Critical, Important, Moderate, Low
	Advisory string `json:"advisory"` // e.g. RHSA-2026:1234
}

// PackageIntegrity holds dependency and shared-library integrity results.
type PackageIntegrity struct {
	BrokenPackages  []string `json:"broken_packages,omitempty"`   // dpkg --audit / dnf check output
	UnmetDeps       []string `json:"unmet_deps,omitempty"`        // apt-get check unmet deps
	MissingLibs     []string `json:"missing_libs,omitempty"`      // ldd on canary bins
	RPMVerifyFailed []string `json:"rpm_verify_failed,omitempty"` // rpm --verify anomalies
	LdconfigOK      bool     `json:"ldconfig_ok"`
	VerifyTimedOut  bool     `json:"verify_timed_out,omitempty"`
}

// PackagesInfo holds package security advisory data.
type PackagesInfo struct {
	Checked            bool              `json:"checked"` // true when package manager was queried successfully
	SecurityUpdates    int               `json:"security_updates"`
	CriticalUpdates    int               `json:"critical_updates"`
	ImportantUpdates   int               `json:"important_updates"`
	ESMUpdates         int               `json:"esm_updates,omitempty"`
	Updates            []PackageUpdate   `json:"updates,omitempty"`
	PackageManager     string            `json:"package_manager"` // dnf, apt, zypper, brew
	HasSecurityRepo    bool              `json:"has_security_repo,omitempty"`
	Integrity          *PackageIntegrity `json:"integrity,omitempty"` // populated in deep mode
	SUSEMigrationRisks []string          `json:"suse_migration_risks,omitempty"`
	Status             string            `json:"status,omitempty"`
	StatusReason       string            `json:"status_reason,omitempty"`
	// MetadataAgeDays is the age of the newest update-metadata cache (apt lists /
	// dnf+zypper repodata); -1 when no metadata cache was found. Used to mark a
	// "0 updates" result unverified when the metadata is stale/absent rather than
	// claiming "up to date" on data that was never refreshed.
	MetadataAgeDays int `json:"metadata_age_days,omitempty"`
}
