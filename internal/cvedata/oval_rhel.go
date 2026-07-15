//go:build linux

package cvedata

import (
	"compress/bzip2"
	"context"
	"encoding/xml"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"
)

// RHELCVERecord holds CVE data extracted from a Red Hat OVAL file.
// Red Hat OVAL encodes CVSS3 scores directly in the advisory section —
// no need to walk the test/object/state tree for package matching.
type RHELCVERecord struct {
	CVEID       string   // e.g. "CVE-2024-3094"
	CVSS3       float64  // base score, e.g. 9.1
	CVSS3Vector string   // e.g. "CVSS:3.1/AV:N/AC:L/..."
	Severity    string   // Critical / Important / Moderate / Low
	Components  []string // affected package names (e.g. ["tar", "tar-devel"])
	State       string   // "Affected" / "Will not fix" / "Fix deferred" / "Not affected"
}

// rhOVALDefs is the minimal XML structure for Red Hat OVAL.
type rhOVALDefs struct {
	Definitions []rhOVALDef `xml:"definitions>definition"`
}

type rhOVALDef struct {
	Class    string     `xml:"class,attr"`
	Metadata rhOVALMeta `xml:"metadata"`
}

type rhOVALMeta struct {
	References []rhOVALRef    `xml:"reference"`
	Advisory   rhOVALAdvisory `xml:"advisory"`
}

type rhOVALRef struct {
	Source string `xml:"source,attr"`
	RefID  string `xml:"ref_id,attr"`
}

type rhOVALAdvisory struct {
	Severity string           `xml:"severity"`
	CVEs     []rhOVALCVE      `xml:"cve"`
	Affected []rhOVALAffected `xml:"affected"`
}

type rhOVALCVE struct {
	CVSS3  string `xml:"cvss3,attr"`  // "7.0/CVSS:3.1/AV:L/AC:H/..."
	Impact string `xml:"impact,attr"` // "moderate"
	Value  string `xml:",chardata"`   // "CVE-2005-2541"
}

type rhOVALAffected struct {
	Resolutions []rhOVALResolution `xml:"resolution"`
}

type rhOVALResolution struct {
	State      string   `xml:"state,attr"` // "Affected", "Will not fix", etc.
	Components []string `xml:"component"`
}

// ParseRHELOVAL reads a Red Hat OVAL file (bzip2 or plain XML) and returns
// a map of CVE ID → RHELCVERecord. Only "vulnerability" class definitions
// with at least one CVE reference are included.
func ParseRHELOVAL(ovalPath string) (map[string]RHELCVERecord, error) {
	f, err := os.Open(ovalPath) // #nosec G304
	if err != nil {
		return nil, fmt.Errorf("opening OVAL: %w", err)
	}
	defer f.Close() //nolint:errcheck

	var r io.Reader = f
	if strings.HasSuffix(strings.ToLower(ovalPath), ".bz2") {
		r = bzip2.NewReader(f)
	}

	var defs rhOVALDefs
	if err := xml.NewDecoder(r).Decode(&defs); err != nil {
		return nil, fmt.Errorf("parsing OVAL XML: %w", err)
	}

	result := make(map[string]RHELCVERecord, len(defs.Definitions)/4)

	for _, def := range defs.Definitions {
		if def.Class != "vulnerability" {
			continue
		}
		// Extract CVE IDs from references
		var cveIDs []string
		for _, ref := range def.Metadata.References {
			if strings.EqualFold(ref.Source, "CVE") && strings.HasPrefix(ref.RefID, "CVE-") {
				cveIDs = append(cveIDs, strings.ToUpper(ref.RefID))
			}
		}
		if len(cveIDs) == 0 {
			continue
		}

		adv := def.Metadata.Advisory
		severity := strings.TrimSpace(adv.Severity)

		// Extract best CVSS3 score across all <cve> elements
		var bestScore float64
		var bestVector string
		for _, c := range adv.CVEs {
			score, vec := parseCVSS3Attr(c.CVSS3)
			if score > bestScore {
				bestScore = score
				bestVector = vec
			}
		}

		// Collect affected components and resolution state
		var components []string
		state := ""
		seen := map[string]bool{}
		for _, aff := range adv.Affected {
			for _, res := range aff.Resolutions {
				if state == "" {
					state = res.State
				}
				for _, comp := range res.Components {
					comp = strings.TrimSpace(comp)
					if comp != "" && !seen[comp] {
						components = append(components, comp)
						seen[comp] = true
					}
				}
			}
		}

		// Store one record per CVE ID
		for _, cveID := range cveIDs {
			rec := RHELCVERecord{
				CVEID:       cveID,
				CVSS3:       bestScore,
				CVSS3Vector: bestVector,
				Severity:    severity,
				Components:  components,
				State:       state,
			}
			// Keep highest CVSS score if CVE appears in multiple definitions
			if existing, ok := result[cveID]; ok {
				if bestScore > existing.CVSS3 {
					result[cveID] = rec
				}
			} else {
				result[cveID] = rec
			}
		}
	}

	return result, nil
}

// parseCVSS3Attr parses the cvss3 attribute: "7.0/CVSS:3.1/AV:L/AC:H/..."
// Returns (score, vector). Returns (0, "") on parse failure.
func parseCVSS3Attr(attr string) (float64, string) {
	if attr == "" {
		return 0, ""
	}
	// Format: "SCORE/VECTOR" e.g. "9.1/CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
	idx := strings.Index(attr, "/")
	if idx < 0 {
		return 0, ""
	}
	score, err := strconv.ParseFloat(attr[:idx], 64)
	if err != nil {
		return 0, ""
	}
	return score, attr[idx+1:]
}

// OVALCVSSResult is a single CVE found vulnerable via OVAL scan.
type OVALCVSSResult struct {
	CVEID      string
	CVSS3      float64
	Severity   string   // Critical / Important / Moderate / Low
	State      string   // resolution state
	Components []string // all affected package names in OVAL
	Installed  []string // subset of Components actually installed on this system
}

// ScanOVALPackages parses an OVAL file and cross-references with installed
// packages. It detects the vendor (RHEL, Ubuntu/Debian, or SUSE) by sniffing
// the file CONTENT first, falling back to the path. Content wins because a
// path-only guess silently routes a renamed SUSE feed (e.g. saved as
// "oval.xml") to the RHEL parser, which finds nothing and reports a green
// "no vulnerable packages" — the false-OK this dispatch exists to avoid.
func ScanOVALPackages(ctx context.Context, ovalPath string) ([]OVALCVSSResult, error) {
	switch sniffOVALVendor(ovalPath) {
	case "ubuntu":
		return ScanUbuntuOVALPackages(ctx, ovalPath)
	case "suse":
		return ScanSUSEOVALPackages(ctx, ovalPath)
	case "rhel":
		return scanRHELOVALPackages(ctx, ovalPath)
	}
	// Content was inconclusive — fall back to the filename hint.
	if isUbuntuOVAL(ovalPath) {
		return ScanUbuntuOVALPackages(ctx, ovalPath)
	}
	if isSUSEOVAL(ovalPath) {
		return ScanSUSEOVALPackages(ctx, ovalPath)
	}
	return scanRHELOVALPackages(ctx, ovalPath)
}

// sniffOVALVendor reads the head of an OVAL file (bzip2-aware) and returns
// "suse", "ubuntu", "rhel", or "" when the vendor can't be told from content.
// The markers are vendor namespace/definition-ID prefixes that appear near the
// top of every real feed.
func sniffOVALVendor(path string) string {
	f, err := os.Open(path) // #nosec G304 -- user-supplied path intentional
	if err != nil {
		return ""
	}
	defer f.Close() //nolint:errcheck

	var r io.Reader = f
	if strings.HasSuffix(strings.ToLower(path), ".bz2") {
		r = bzip2.NewReader(f)
	}
	buf := make([]byte, 64*1024)
	n, _ := io.ReadFull(r, buf)
	head := strings.ToLower(string(buf[:n]))
	switch {
	case strings.Contains(head, "opensuse.security") || strings.Contains(head, "suse.de") ||
		strings.Contains(head, "org.opensuse") || strings.Contains(head, "suse.linux.enterprise"):
		return "suse"
	case strings.Contains(head, "canonical") || strings.Contains(head, "ubuntu.com") ||
		strings.Contains(head, "com.ubuntu"):
		return "ubuntu"
	case strings.Contains(head, "com.redhat") || strings.Contains(head, "redhat.com") ||
		strings.Contains(head, "rhsa") || strings.Contains(head, "rhel"):
		return "rhel"
	}
	return ""
}

// isSUSEOVAL returns true when the OVAL file path indicates SUSE/openSUSE origin.
func isSUSEOVAL(path string) bool {
	lower := strings.ToLower(path)
	return strings.Contains(lower, "suse") ||
		strings.Contains(lower, "opensuse") ||
		strings.Contains(lower, "sles")
}

// isUbuntuOVAL returns true when the OVAL file path indicates Ubuntu/Debian origin.
func isUbuntuOVAL(path string) bool {
	lower := strings.ToLower(path)
	return strings.Contains(lower, "ubuntu") ||
		strings.Contains(lower, "debian") ||
		strings.Contains(lower, "canonical")
}

// scanRHELOVALPackages is the original RHEL/Rocky/AlmaLinux OVAL scanner.
func scanRHELOVALPackages(ctx context.Context, ovalPath string) ([]OVALCVSSResult, error) {
	// Parse OVAL
	cveMap, err := ParseRHELOVAL(ovalPath)
	if err != nil {
		return nil, err
	}

	// Get installed packages
	pkgs, err := QueryInstalledRPM(ctx)
	if err != nil {
		return nil, fmt.Errorf("querying installed packages: %w", err)
	}
	installed := make(map[string]bool, len(pkgs))
	for _, p := range pkgs {
		installed[strings.ToLower(p.Name)] = true
	}

	var results []OVALCVSSResult
	for _, rec := range cveMap {
		// Skip non-fixable / not-affected resolutions
		stateLower := strings.ToLower(rec.State)
		if strings.Contains(stateLower, "will not fix") ||
			strings.Contains(stateLower, "fix deferred") ||
			strings.Contains(stateLower, "not affected") {
			continue
		}

		if res, ok := ovalBuildResult(installed, rec); ok {
			results = append(results, res)
		}
	}

	// Sort by CVSS descending
	sortOVALResults(results)
	return results, nil
}

// cvssLevel returns the DashDiag severity bucket for a CVSS3 score.
// Critical ≥9.0, High ≥7.0, Medium ≥4.0, Low <4.0.
func cvssLevel(score float64) string {
	switch {
	case score >= 9.0:
		return "Critical"
	case score >= 7.0:
		return "High"
	case score >= 4.0:
		return "Medium"
	default:
		return "Low"
	}
}

// sortOVALResults sorts results by CVSS descending, then CVE ID ascending.
func sortOVALResults(results []OVALCVSSResult) {
	for i := 1; i < len(results); i++ {
		for j := i; j > 0 && results[j].CVSS3 > results[j-1].CVSS3; j-- {
			results[j], results[j-1] = results[j-1], results[j]
		}
	}
}
