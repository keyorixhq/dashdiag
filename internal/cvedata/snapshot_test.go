package cvedata

import (
	"compress/gzip"
	"os"
	"path/filepath"
	"testing"
)

// TestOVALFileCandidates pins the distro -> OVAL-filename mapping (the offline
// CVE-database file resolution) for each supported family.
func TestOVALFileCandidates(t *testing.T) {
	tests := []struct {
		distro   string
		wantFile string // a filename that must appear in the candidate list
	}{
		{"SLES 15", "sles15.xml.bz2"},
		{"openSUSE Tumbleweed", "tumbleweed.xml.bz2"},
		{"rhel 9", "rhel-9.oval.xml.bz2"},
		{"Rocky Linux 9", "rocky-linux-9.oval.xml.bz2"},
		{"Fedora 40", "fedora.xml.bz2"},
		{"Ubuntu 24.04", "ubuntu-noble.oval.xml.bz2"},
		{"Debian 13", "debian-trixie.oval.xml.bz2"},
	}
	for _, tt := range tests {
		t.Run(tt.distro, func(t *testing.T) {
			got := ovalFileCandidates(tt.distro)
			found := false
			for _, c := range got {
				if c == tt.wantFile {
					found = true
				}
			}
			if !found {
				t.Errorf("ovalFileCandidates(%q) = %v, want it to contain %q", tt.distro, got, tt.wantFile)
			}
		})
	}
	if got := ovalFileCandidates("PlatformNine"); got != nil {
		t.Errorf("unknown distro should yield nil candidates, got %v", got)
	}
}

func TestSnapshot_IsEmptyAndLookup(t *testing.T) {
	empty := &Snapshot{CVEs: map[string]SnapshotCVE{}}
	if !empty.IsEmpty() {
		t.Error("empty snapshot should report IsEmpty")
	}
	s := &Snapshot{CVEs: map[string]SnapshotCVE{
		"CVE-2021-1234": {Summary: "test flaw", Severity: "High"},
	}}
	if s.IsEmpty() {
		t.Error("populated snapshot should not be empty")
	}
	if cve, ok := s.Lookup("CVE-2021-1234"); !ok || cve.Severity != "High" {
		t.Errorf("Lookup hit = %+v, %v", cve, ok)
	}
	// Case-insensitive: a lower-case query must still hit (keys are upper-case).
	if cve, ok := s.Lookup("cve-2021-1234"); !ok || cve.Severity != "High" {
		t.Errorf("case-insensitive Lookup = %+v, %v; want hit", cve, ok)
	}
	if _, ok := s.Lookup("CVE-9999-0000"); ok {
		t.Error("Lookup of an absent CVE should miss")
	}
}

const snapshotJSON = `{
  "_source": "test-feed",
  "cves": {
    "CVE-2021-1234": {"summary": "buffer overflow", "severity": "Critical",
      "affected": {"libfoo": [{"name": "libfoo", "fixed_version": "1.2.3"}]}}
  }
}`

func TestLoadSnapshot_JSON(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "cvedata.json")
	if err := os.WriteFile(path, []byte(snapshotJSON), 0o600); err != nil {
		t.Fatal(err)
	}
	s, err := LoadSnapshot(path)
	if err != nil {
		t.Fatalf("LoadSnapshot: %v", err)
	}
	if s.Source != "test-feed" {
		t.Errorf("Source = %q", s.Source)
	}
	if cve, ok := s.Lookup("CVE-2021-1234"); !ok || cve.Severity != "Critical" {
		t.Errorf("loaded CVE = %+v, %v", cve, ok)
	}
}

func TestLoadSnapshot_Gzip(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "cvedata.json.gz")
	f, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	gw := gzip.NewWriter(f)
	if _, err := gw.Write([]byte(snapshotJSON)); err != nil {
		t.Fatal(err)
	}
	_ = gw.Close()
	_ = f.Close()

	s, err := LoadSnapshot(path)
	if err != nil {
		t.Fatalf("LoadSnapshot (gzip): %v", err)
	}
	if _, ok := s.Lookup("CVE-2021-1234"); !ok {
		t.Error("gzip snapshot should contain the CVE")
	}
}

func TestLoadSnapshot_Errors(t *testing.T) {
	if _, err := LoadSnapshot("/nonexistent/cvedata.json"); err == nil {
		t.Error("missing file should error")
	}
	dir := t.TempDir()
	bad := filepath.Join(dir, "bad.json")
	if err := os.WriteFile(bad, []byte("{not json"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadSnapshot(bad); err == nil {
		t.Error("malformed JSON should error")
	}
}
