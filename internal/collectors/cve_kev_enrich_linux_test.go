//go:build linux

package collectors

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/keyorixhq/dashdiag/internal/models"
)

// TestEnrichCVEAllWithKEV_NilResultNoPanic guards the nil-guard: calling with a
// nil result must be a safe no-op, never a panic — EnrichCVEAllWithKEV is
// called unconditionally from every CVE entrypoint regardless of scan outcome.
func TestEnrichCVEAllWithKEV_NilResultNoPanic(t *testing.T) {
	t.Parallel()
	EnrichCVEAllWithKEV(nil) // must not panic
}

// TestEnrichCVEAllWithKEV_NoCatalogAvailable guards the common no-op path: on a
// host with no KEV sidecar file anywhere on the standard search paths, the
// result must be left completely unannotated (KEVCount==0), not erroring or
// fabricating a match.
func TestEnrichCVEAllWithKEV_NoCatalogAvailable(t *testing.T) {
	isolateCVEHome(t) // fresh HOME — none of the standard KEV dirs exist under it
	r := &models.CVEAllResult{
		Critical: []models.CVEAdvisory{{ID: "RHSA-1", CVEs: "CVE-2021-44228"}},
	}
	EnrichCVEAllWithKEV(r)
	if r.KEVCount != 0 || r.KEVCVEs != nil {
		t.Errorf("expected no KEV annotation with no catalog file present, got %+v", r)
	}
	// No sidecar file anywhere is the normal, expected state for most hosts —
	// must NOT be conflated with a present-but-broken catalog.
	if r.KEVCatalogReadFailed {
		t.Errorf("a missing catalog is not a load failure, got KEVCatalogReadFailed=true")
	}
}

// TestEnrichCVEAllWithKEV_CatalogFileMalformed guards the LoadKEV-error branch:
// a catalog file that EXISTS but fails to parse (malformed JSON) must leave the
// result unannotated (return early), not panic or propagate the parse error —
// but, unlike a genuinely-absent catalog (internal-collectors-06-03), it must
// mark KEVCatalogReadFailed so the analysis layer can disclose that KEV
// cross-referencing did not actually run, instead of reading identically to
// "no catalog available".
func TestEnrichCVEAllWithKEV_CatalogFileMalformed(t *testing.T) {
	home := isolateCVEHome(t)
	kevDir := filepath.Join(home, ".dsd", "kev")
	if err := os.MkdirAll(kevDir, 0o755); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(kevDir, "known_exploited_vulnerabilities.json")
	if err := os.WriteFile(path, []byte("{not valid json"), 0o600); err != nil {
		t.Fatal(err)
	}

	r := &models.CVEAllResult{
		Critical: []models.CVEAdvisory{{ID: "RHSA-1", CVEs: "CVE-2021-44228"}},
	}
	EnrichCVEAllWithKEV(r)
	if r.KEVCount != 0 || r.KEVCVEs != nil {
		t.Errorf("a malformed catalog file must leave the result unannotated, got %+v", r)
	}
	if !r.KEVCatalogReadFailed {
		t.Errorf("a present-but-malformed catalog must set KEVCatalogReadFailed, got false")
	}
}

// TestEnrichCVEAllWithKEV_CatalogFoundAndMatched guards the full path: a KEV
// catalog staged under the standard ~/.dsd/kev directory must be loaded and
// used to annotate a matching pending advisory.
func TestEnrichCVEAllWithKEV_CatalogFoundAndMatched(t *testing.T) {
	home := isolateCVEHome(t)
	kevDir := filepath.Join(home, ".dsd", "kev")
	if err := os.MkdirAll(kevDir, 0o755); err != nil {
		t.Fatal(err)
	}
	body := `{
		"catalogVersion": "test",
		"vulnerabilities": [
			{"cveID": "CVE-2021-44228", "dateAdded": "2021-12-10", "knownRansomwareCampaignUse": "Known"}
		]
	}`
	path := filepath.Join(kevDir, "known_exploited_vulnerabilities.json")
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}

	r := &models.CVEAllResult{
		Critical: []models.CVEAdvisory{{ID: "RHSA-1", CVEs: "CVE-2021-44228"}},
	}
	EnrichCVEAllWithKEV(r)
	if r.KEVCount != 1 {
		t.Fatalf("KEVCount = %d, want 1", r.KEVCount)
	}
	if len(r.KEVCVEs) != 1 || r.KEVCVEs[0] != "CVE-2021-44228" {
		t.Errorf("KEVCVEs = %v, want [CVE-2021-44228]", r.KEVCVEs)
	}
}
