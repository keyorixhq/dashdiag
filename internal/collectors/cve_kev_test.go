package collectors

import (
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/keyorixhq/dashdiag/internal/cvedata"
	"github.com/keyorixhq/dashdiag/internal/models"
)

func loadTestKEV(t *testing.T) *cvedata.KEVCatalog {
	t.Helper()
	body := `{
      "catalogVersion": "test",
      "vulnerabilities": [
        {"cveID": "CVE-2021-44228", "dateAdded": "2021-12-10", "knownRansomwareCampaignUse": "Known"},
        {"cveID": "CVE-2024-3094", "dateAdded": "2024-04-02", "knownRansomwareCampaignUse": "Unknown"}
      ]
    }`
	path := filepath.Join(t.TempDir(), "kev.json")
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	cat, err := cvedata.LoadKEV(path)
	if err != nil {
		t.Fatal(err)
	}
	return cat
}

func TestAnnotateCVEResultWithKEV(t *testing.T) {
	cat := loadTestKEV(t)

	hit := &models.CVEResult{CVE: "CVE-2021-44228"}
	annotateCVEResultWithKEV(cat, hit)
	if !hit.KnownExploited {
		t.Error("expected KnownExploited=true for Log4Shell")
	}
	if !hit.KEVRansomware {
		t.Error("expected KEVRansomware=true for Log4Shell")
	}
	if hit.KEVDateAdded != "2021-12-10" {
		t.Errorf("KEVDateAdded = %q", hit.KEVDateAdded)
	}

	miss := &models.CVEResult{CVE: "CVE-2000-0001"}
	annotateCVEResultWithKEV(cat, miss)
	if miss.KnownExploited {
		t.Error("absent CVE should not be flagged")
	}
}

func TestAnnotateCVEResultNilCatalogNoPanic(t *testing.T) {
	r := &models.CVEResult{CVE: "CVE-2021-44228"}
	annotateCVEResultWithKEV(nil, r)
	if r.KnownExploited {
		t.Error("nil catalog must not flag anything")
	}
}

func TestAnnotateCVEAllWithKEV(t *testing.T) {
	cat := loadTestKEV(t)
	r := &models.CVEAllResult{
		Critical: []models.CVEAdvisory{
			{ID: "RHSA-1", CVEs: "CVE-2021-44228, CVE-2021-9999"},
		},
		Important: []models.CVEAdvisory{
			{ID: "RHSA-2", CVEs: "CVE-2024-3094"},
			{ID: "RHSA-3", CVEs: "CVE-2000-0001"}, // not in KEV
		},
	}
	annotateCVEAllWithKEV(cat, r)
	if r.KEVCount != 2 {
		t.Fatalf("KEVCount = %d, want 2", r.KEVCount)
	}
	want := []string{"CVE-2021-44228", "CVE-2024-3094"}
	if !reflect.DeepEqual(r.KEVCVEs, want) {
		t.Errorf("KEVCVEs = %v, want %v", r.KEVCVEs, want)
	}
}

func TestAnnotateCVEAllDeduplicates(t *testing.T) {
	cat := loadTestKEV(t)
	r := &models.CVEAllResult{
		Critical:  []models.CVEAdvisory{{ID: "A", CVEs: "CVE-2021-44228"}},
		Important: []models.CVEAdvisory{{ID: "B", CVEs: "CVE-2021-44228"}}, // same CVE twice
	}
	annotateCVEAllWithKEV(cat, r)
	if r.KEVCount != 1 {
		t.Errorf("KEVCount = %d, want 1 (deduped)", r.KEVCount)
	}
}

func TestExtractCVEIDs(t *testing.T) {
	cases := map[string][]string{
		"":                              nil,
		"CVE-2021-44228":                {"CVE-2021-44228"},
		"cve-2021-44228, CVE-2024-3094": {"CVE-2021-44228", "CVE-2024-3094"},
		"no cve here":                   nil,
		"CVE-2021-123456 padded":        {"CVE-2021-123456"},
	}
	for in, want := range cases {
		got := extractCVEIDs(in)
		if !reflect.DeepEqual(got, want) {
			t.Errorf("extractCVEIDs(%q) = %v, want %v", in, got, want)
		}
	}
}
