package cvedata

// InstalledPackage holds name and EVR (epoch:version-release) from rpm.
type InstalledPackage struct {
	Name string
	EVR  string // e.g. "0:1.9.14p3-2.1" or "1.9.14p3-2.1"
}

// OVALResult holds the outcome of an OVAL-based CVE check.
type OVALResult struct {
	CVE      string
	Found    bool // CVE definition present in OVAL file
	Severity string
	Summary  string
	Packages []OVALPackageMatch
}

// OVALPackageMatch is a package found vulnerable by OVAL evaluation.
type OVALPackageMatch struct {
	Name      string
	Installed string // installed EVR
	FixedIn   string // first safe EVR from OVAL
}
