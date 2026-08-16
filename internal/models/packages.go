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
	VerifyLocked    bool     `json:"verify_locked,omitempty"` // integrity check couldn't run — package manager was locked
	// CheckFailed is true when the underlying integrity tool itself (dnf
	// check / rpm --verify / dpkg --audit / apt-get check) failed to spawn or
	// run at all — a genuine execution failure, not "ran and found nothing."
	// Those commands are read via runCmdOutput/runCmdCombined specifically so
	// their non-zero-exit findings survive (see pkgIntegrityDNF/APT), which
	// means empty stdout alone can't distinguish "verified clean" from "never
	// ran" — this flag closes that gap.
	CheckFailed bool `json:"check_failed,omitempty"`
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

	// --- Package-DB / lock health: a state that silently blocks ALL updates ---
	// DBHealthChecked is true when a DB/lock probe ran for this manager.
	// DBUpdatesBlocked is set when the package DB is in a state — an interrupted dpkg
	// (apt), or an unreadable/corrupt rpmdb (dnf/yum/zypper, all rpm-based) — that
	// makes every update silently fail: the host reports "0 updates" but literally
	// cannot apply any. This is the false-OK the check exists to catch.
	// DBBlockReason/DBBlockFix carry the diagnosis and remedy.
	DBHealthChecked  bool   `json:"db_health_checked"`
	DBUpdatesBlocked bool   `json:"db_updates_blocked,omitempty"`
	DBBlockReason    string `json:"db_block_reason,omitempty"`
	DBBlockFix       string `json:"db_block_fix,omitempty"`
}
