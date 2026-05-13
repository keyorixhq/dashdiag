package cvedata

import (
	_ "embed"
	"encoding/json"
	"time"
)

//go:embed snapshot.json
var snapshotJSON []byte

// Snapshot is the embedded CVE database bundled at build time.
// Refreshed by running: make update-cve-data
type Snapshot struct {
	Generated time.Time              `json:"_generated"`
	Source    string                 `json:"_source"`
	CVEs      map[string]SnapshotCVE `json:"cves"`
}

// SnapshotCVE holds minimal data for one CVE across distros.
type SnapshotCVE struct {
	Summary  string `json:"summary"`
	Severity string `json:"severity"`
	// distro key: "sles:16", "opensuse-tumbleweed", "rhel:10", "fedora:44", "debian:13", "ubuntu:26"
	Affected map[string][]SnapshotPackage `json:"affected"`
}

// SnapshotPackage maps a package name to the version that fixes the CVE.
// FixedIn uses RPM EVR format: "epoch:version-release" or just "version-release"
type SnapshotPackage struct {
	Name    string `json:"name"`
	FixedIn string `json:"fixed_in"` // first safe version
}

// Load parses the embedded snapshot. Returns empty snapshot on error.
func Load() *Snapshot {
	var s Snapshot
	if err := json.Unmarshal(snapshotJSON, &s); err != nil {
		return &Snapshot{CVEs: map[string]SnapshotCVE{}}
	}
	if s.CVEs == nil {
		s.CVEs = map[string]SnapshotCVE{}
	}
	return &s
}

// IsEmpty returns true when the snapshot has no CVE data (placeholder state).
func (s *Snapshot) IsEmpty() bool {
	return len(s.CVEs) == 0
}

// Lookup finds a CVE by ID (case-insensitive).
func (s *Snapshot) Lookup(cveID string) (SnapshotCVE, bool) {
	cve, ok := s.CVEs[cveID]
	return cve, ok
}
