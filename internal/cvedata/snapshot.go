package cvedata

import (
	"bytes"
	"compress/gzip"
	_ "embed"
	"encoding/json"
	"io"
	"time"
)

//go:embed snapshot.json.gz
var snapshotGZ []byte

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
	// distro key: "sles:16", "opensuse-tumbleweed"
	Affected map[string][]SnapshotPackage `json:"affected"`
}

// SnapshotPackage maps a package name to the version that fixes the CVE.
type SnapshotPackage struct {
	Name    string `json:"name"`
	FixedIn string `json:"fixed_in"`
}

// Load decompresses and parses the embedded snapshot. Returns empty on error.
func Load() *Snapshot {
	r, err := gzip.NewReader(bytes.NewReader(snapshotGZ))
	if err != nil {
		return &Snapshot{CVEs: map[string]SnapshotCVE{}}
	}
	defer func() { _ = r.Close() }()
	data, err := io.ReadAll(r)
	if err != nil {
		return &Snapshot{CVEs: map[string]SnapshotCVE{}}
	}
	var s Snapshot
	if err := json.Unmarshal(data, &s); err != nil {
		return &Snapshot{CVEs: map[string]SnapshotCVE{}}
	}
	if s.CVEs == nil {
		s.CVEs = map[string]SnapshotCVE{}
	}
	return &s
}

// IsEmpty returns true when the snapshot has no CVE data.
func (s *Snapshot) IsEmpty() bool { return len(s.CVEs) == 0 }

// Lookup finds a CVE by ID.
func (s *Snapshot) Lookup(cveID string) (SnapshotCVE, bool) {
	cve, ok := s.CVEs[cveID]
	return cve, ok
}
