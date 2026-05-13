package models

// CVEStatus indicates whether a system is affected by a CVE.
type CVEStatus string

const (
	CVEVulnerable  CVEStatus = "VULNERABLE"   // fix available but not installed
	CVEPatched     CVEStatus = "PATCHED"      // fix installed, not vulnerable
	CVENotAffected CVEStatus = "NOT_AFFECTED" // package not installed / not in scope
	CVEUnknown     CVEStatus = "UNKNOWN"      // package manager can't determine
)

// CVEResult holds the result of a CVE check for one package manager.
type CVEResult struct {
	CVE            string    `json:"cve"`
	Status         CVEStatus `json:"status"`
	PackageManager string    `json:"package_manager"`

	// Populated when VULNERABLE
	AffectedPackages []CVEPackage `json:"affected_packages,omitempty"`
	FixAdvisory      string       `json:"fix_advisory,omitempty"` // e.g. SUSE-SLE-2024-1234
	FixCommand       string       `json:"fix_command,omitempty"`  // e.g. zypper patch --cve CVE-...

	// Populated when UNKNOWN
	FallbackURL string `json:"fallback_url,omitempty"`

	StatusReason string `json:"status_reason,omitempty"`
}

// CVEAllResult holds the full security advisory scan from a package manager.
type CVEAllResult struct {
	PackageManager string        `json:"package_manager"`
	Total          int           `json:"total"`
	Critical       []CVEAdvisory `json:"critical,omitempty"`
	Important      []CVEAdvisory `json:"important,omitempty"`
	Moderate       []CVEAdvisory `json:"moderate,omitempty"`
	Low            []CVEAdvisory `json:"low,omitempty"`
	FixCommand     string        `json:"fix_command,omitempty"`
	StatusReason   string        `json:"status_reason,omitempty"`
}

// CVEAdvisory is one pending security advisory from a full scan.
type CVEAdvisory struct {
	ID       string `json:"id"`   // advisory ID e.g. SUSE-SLE-2025-1234
	CVEs     string `json:"cves"` // CVE IDs associated
	Severity string `json:"severity"`
	Summary  string `json:"summary"`
}

// CVEPackage describes a package affected by a CVE.
type CVEPackage struct {
	Name     string `json:"name"`
	Version  string `json:"version,omitempty"`  // installed version
	FixedIn  string `json:"fixed_in,omitempty"` // version that fixes it
	Advisory string `json:"advisory,omitempty"` // advisory ID
	Severity string `json:"severity,omitempty"` // critical, important, moderate
}
