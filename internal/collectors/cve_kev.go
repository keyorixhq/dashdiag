package collectors

import (
	"regexp"
	"strings"

	"github.com/keyorixhq/dashdiag/internal/cvedata"
	"github.com/keyorixhq/dashdiag/internal/models"
)

// cveIDPattern matches CVE identifiers anywhere in a string so KEV cross-referencing
// works against advisory fields that pack multiple CVE IDs into one comma- or
// space-separated value (e.g. "CVE-2021-1234, CVE-2021-5678").
var cveIDPattern = regexp.MustCompile(`(?i)CVE-\d{4}-\d{4,}`)

// annotateCVEResultWithKEV sets the KEV fields on a single CVE result when the
// CVE is present in the CISA Known Exploited Vulnerabilities catalog. A nil
// catalog (no sidecar file) leaves the result unchanged.
func annotateCVEResultWithKEV(cat *cvedata.KEVCatalog, r *models.CVEResult) {
	if cat == nil || r == nil {
		return
	}
	entry, ok := cat.Lookup(r.CVE)
	if !ok {
		return
	}
	r.KnownExploited = true
	r.KEVDateAdded = entry.DateAdded
	r.KEVRansomware = entry.IsRansomware()
}

// annotateCVEAllWithKEV counts how many pending advisories carry a CVE that is
// in the CISA KEV catalog, recording the matching CVE IDs on the result. This
// drives CRIT escalation in the health collector and the standalone scan.
func annotateCVEAllWithKEV(cat *cvedata.KEVCatalog, r *models.CVEAllResult) {
	if cat == nil || r == nil || cat.Count() == 0 {
		return
	}
	seen := make(map[string]bool)
	var matched []string

	scan := func(advisories []models.CVEAdvisory) {
		for _, a := range advisories {
			for _, id := range extractCVEIDs(a.CVEs) {
				if seen[id] || !cat.Contains(id) {
					continue
				}
				seen[id] = true
				matched = append(matched, id)
			}
		}
	}
	scan(r.Critical)
	scan(r.Important)
	scan(r.Moderate)
	scan(r.Low)

	r.KEVCount = len(matched)
	r.KEVCVEs = matched
}

// EnrichCVEAllWithKEV loads the CISA KEV catalog from standard sidecar paths (if
// present) and annotates the scan result with how many pending advisories are
// actively exploited. No-op when no catalog file is available, so it is safe to
// call unconditionally on any host.
func EnrichCVEAllWithKEV(r *models.CVEAllResult) {
	if r == nil {
		return
	}
	cat, err := cvedata.LoadKEVFromStandardPaths()
	if err != nil {
		return
	}
	annotateCVEAllWithKEV(cat, r)
}

// extractCVEIDs pulls all upper-cased CVE identifiers out of a free-form string.
func extractCVEIDs(s string) []string {
	if s == "" {
		return nil
	}
	matches := cveIDPattern.FindAllString(s, -1)
	for i := range matches {
		matches[i] = strings.ToUpper(matches[i])
	}
	return matches
}
