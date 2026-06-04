package cvedata

import (
	"os"
	"path/filepath"
	"testing"
)

const sampleKEV = `{
  "title": "CISA Catalog of Known Exploited Vulnerabilities",
  "catalogVersion": "2026.06.04",
  "dateReleased": "2026-06-04T12:00:00.0000Z",
  "count": 3,
  "vulnerabilities": [
    {
      "cveID": "CVE-2021-44228",
      "vendorProject": "Apache",
      "product": "Log4j2",
      "vulnerabilityName": "Apache Log4j2 RCE",
      "dateAdded": "2021-12-10",
      "dueDate": "2021-12-24",
      "knownRansomwareCampaignUse": "Known"
    },
    {
      "cveID": "CVE-2024-3094",
      "vendorProject": "XZ",
      "product": "liblzma",
      "vulnerabilityName": "XZ backdoor",
      "dateAdded": "2024-04-02",
      "knownRansomwareCampaignUse": "Unknown"
    },
    {
      "cveID": "",
      "vendorProject": "Bogus",
      "product": "Empty"
    }
  ]
}`

func writeKEV(t *testing.T, body string) string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "known_exploited_vulnerabilities.json")
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestLoadKEVParsesAndIndexes(t *testing.T) {
	cat, err := LoadKEV(writeKEV(t, sampleKEV))
	if err != nil {
		t.Fatalf("LoadKEV: %v", err)
	}
	// The empty-cveID entry must be dropped.
	if cat.Count() != 2 {
		t.Errorf("Count() = %d, want 2 (empty cveID dropped)", cat.Count())
	}
	if cat.CatalogVersion != "2026.06.04" {
		t.Errorf("CatalogVersion = %q", cat.CatalogVersion)
	}
}

func TestKEVLookupCaseInsensitive(t *testing.T) {
	cat, err := LoadKEV(writeKEV(t, sampleKEV))
	if err != nil {
		t.Fatal(err)
	}
	e, ok := cat.Lookup("cve-2021-44228") // lower-case input
	if !ok {
		t.Fatal("expected lower-case lookup to hit")
	}
	if e.DateAdded != "2021-12-10" {
		t.Errorf("DateAdded = %q", e.DateAdded)
	}
	if !e.IsRansomware() {
		t.Error("Log4Shell entry should report ransomware use")
	}
}

func TestKEVContainsMissAndNonRansomware(t *testing.T) {
	cat, err := LoadKEV(writeKEV(t, sampleKEV))
	if err != nil {
		t.Fatal(err)
	}
	if cat.Contains("CVE-2000-0001") {
		t.Error("unexpected hit for absent CVE")
	}
	e, ok := cat.Lookup("CVE-2024-3094")
	if !ok {
		t.Fatal("expected XZ CVE to be present")
	}
	if e.IsRansomware() {
		t.Error("XZ entry is 'Unknown' ransomware — should be false")
	}
}

func TestNilCatalogIsSafe(t *testing.T) {
	var cat *KEVCatalog
	if cat.Count() != 0 {
		t.Error("nil catalog Count should be 0")
	}
	if cat.Contains("CVE-2021-44228") {
		t.Error("nil catalog should never match")
	}
	if _, ok := cat.Lookup("CVE-2021-44228"); ok {
		t.Error("nil catalog Lookup should miss")
	}
}

func TestLoadKEVBadFile(t *testing.T) {
	if _, err := LoadKEV(filepath.Join(t.TempDir(), "nope.json")); err == nil {
		t.Error("expected error for missing file")
	}
	bad := writeKEV(t, "{not json")
	if _, err := LoadKEV(bad); err == nil {
		t.Error("expected parse error for malformed JSON")
	}
}
