package cvedata

import (
	"compress/gzip"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

// KEV — CISA Known Exploited Vulnerabilities catalog.
//
// The catalog is the authoritative list of CVEs that have been exploited in the
// wild. A CVE on this list is materially more urgent than its CVSS score alone
// suggests, so dsd escalates any installed-package CVE found on it to CRIT.
//
// Following the OVAL/snapshot sidecar model, the catalog is read from a local
// file — no mandatory network call, so it works on air-gapped hosts. Fetch it
// with:
//
//	curl -sL https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json \
//	  -o /var/lib/dsd/kev/known_exploited_vulnerabilities.json
//
// Lookup is O(1) — the catalog is indexed by CVE ID on load.

// KEVEntry is one vulnerability in the CISA KEV catalog. Only the fields dsd
// surfaces are decoded; the JSON has more.
type KEVEntry struct {
	CVEID             string `json:"cveID"`
	VendorProject     string `json:"vendorProject"`
	Product           string `json:"product"`
	VulnerabilityName string `json:"vulnerabilityName"`
	DateAdded         string `json:"dateAdded"`
	DueDate           string `json:"dueDate"`
	// knownRansomwareCampaignUse is "Known" or "Unknown" in the CISA feed.
	RansomwareUse string `json:"knownRansomwareCampaignUse"`
}

// IsRansomware reports whether the CVE is tied to a known ransomware campaign.
func (e KEVEntry) IsRansomware() bool {
	return strings.EqualFold(strings.TrimSpace(e.RansomwareUse), "known")
}

// KEVCatalog is the parsed CISA catalog indexed by CVE ID (upper-cased).
type KEVCatalog struct {
	CatalogVersion string              `json:"catalogVersion"`
	DateReleased   string              `json:"dateReleased"`
	byCVE          map[string]KEVEntry `json:"-"`
}

// kevFile mirrors the top-level CISA JSON document for decoding.
type kevFile struct {
	CatalogVersion  string     `json:"catalogVersion"`
	DateReleased    string     `json:"dateReleased"`
	Vulnerabilities []KEVEntry `json:"vulnerabilities"`
}

// Count returns the number of indexed CVEs.
func (c *KEVCatalog) Count() int {
	if c == nil {
		return 0
	}
	return len(c.byCVE)
}

// Lookup returns the catalog entry for a CVE ID, if present. Matching is
// case-insensitive on the CVE ID. A nil catalog never matches.
func (c *KEVCatalog) Lookup(cveID string) (KEVEntry, bool) {
	if c == nil || len(c.byCVE) == 0 {
		return KEVEntry{}, false
	}
	e, ok := c.byCVE[normalizeCVE(cveID)]
	return e, ok
}

// Contains reports whether a CVE ID is in the catalog.
func (c *KEVCatalog) Contains(cveID string) bool {
	_, ok := c.Lookup(cveID)
	return ok
}

func normalizeCVE(id string) string {
	return strings.ToUpper(strings.TrimSpace(id))
}

// KEVStandardPaths returns the locations dsd searches for the catalog file,
// system-wide first then user-local. Mirrors StandardOVALPaths.
func KEVStandardPaths() []string {
	paths := []string{
		"/var/lib/dsd/kev",
		"/etc/dsd/kev",
	}
	if home, err := os.UserHomeDir(); err == nil {
		paths = append(paths,
			filepath.Join(home, ".local", "share", "dsd", "kev"),
			filepath.Join(home, ".dsd", "kev"),
		)
	}
	return paths
}

// FindKEVFile searches the standard paths for a CISA KEV catalog file.
// It accepts the canonical CISA filename, or any *.json / *.json.gz whose name
// contains "kev" or "known_exploited". Returns "" when none is found.
func FindKEVFile() string {
	canonical := []string{
		"known_exploited_vulnerabilities.json",
		"known_exploited_vulnerabilities.json.gz",
	}
	for _, dir := range KEVStandardPaths() {
		for _, name := range canonical {
			path := filepath.Join(dir, name)
			if _, err := os.Stat(path); err == nil {
				return path
			}
		}
		entries, err := os.ReadDir(dir)
		if err != nil {
			continue
		}
		for _, e := range entries {
			if e.IsDir() {
				continue
			}
			lower := strings.ToLower(e.Name())
			isJSON := strings.HasSuffix(lower, ".json") || strings.HasSuffix(lower, ".json.gz")
			if isJSON && (strings.Contains(lower, "kev") || strings.Contains(lower, "known_exploited")) {
				return filepath.Join(dir, e.Name())
			}
		}
	}
	return ""
}

// LoadKEV reads and parses a CISA KEV catalog file (plain JSON or gzip).
func LoadKEV(path string) (*KEVCatalog, error) {
	f, err := os.Open(path) // #nosec G304 -- operator-supplied sidecar path
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()

	var r io.Reader = f
	if strings.HasSuffix(strings.ToLower(path), ".gz") {
		gr, err := gzip.NewReader(f)
		if err != nil {
			return nil, fmt.Errorf("gzip: %w", err)
		}
		defer func() { _ = gr.Close() }()
		r = gr
	}

	var doc kevFile
	if err := json.NewDecoder(r).Decode(&doc); err != nil {
		return nil, fmt.Errorf("parsing KEV catalog: %w", err)
	}

	cat := &KEVCatalog{
		CatalogVersion: doc.CatalogVersion,
		DateReleased:   doc.DateReleased,
		byCVE:          make(map[string]KEVEntry, len(doc.Vulnerabilities)),
	}
	for _, v := range doc.Vulnerabilities {
		if v.CVEID == "" {
			continue
		}
		cat.byCVE[normalizeCVE(v.CVEID)] = v
	}
	return cat, nil
}

// LoadKEVFromStandardPaths finds and loads the catalog from a standard path.
// Returns (nil, nil) when no catalog file is present — callers treat a missing
// catalog as "no KEV data available", not an error.
func LoadKEVFromStandardPaths() (*KEVCatalog, error) {
	path := FindKEVFile()
	if path == "" {
		return nil, nil
	}
	return LoadKEV(path)
}
