//go:build linux

package collectors

import (
	"os"
	"testing"
)

// TestTDNFDifferentialRealPairs verifies a real, dashdiag-independent capture of
// `tdnf -j updateinfo list --security` and `tdnf updateinfo list --security`
// from the SAME Photon OS host at the SAME moment dedupe to the identical
// advisory list via production's parsers + tdnfDedupeAdvisories. Captured
// manually over ssh on a throwaway Photon 5.0 VM (not via dsd) — see
// testdata/differential/tdnf/manifest.json for provenance.
func TestTDNFDifferentialRealPairs(t *testing.T) {
	cases := []struct {
		name           string
		jsonFile       string
		textFile       string
		wantAdvisories int
	}{
		{
			// 29 raw per-package entries (manifest.json) dedupe to 21 unique
			// PHSA advisory IDs — Photon emits one entry per affected package,
			// and several packages here share an advisory.
			name:           "photon5.0 throwaway VM: 21 real deduped security advisories",
			jsonFile:       "../../testdata/differential/tdnf/photon5.0-vm-20260923.json",
			textFile:       "../../testdata/differential/tdnf/photon5.0-vm-20260923.text",
			wantAdvisories: 21,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			jsonBytes, err := os.ReadFile(tc.jsonFile)
			if err != nil {
				t.Fatalf("reading %s: %v", tc.jsonFile, err)
			}
			textBytes, err := os.ReadFile(tc.textFile)
			if err != nil {
				t.Fatalf("reading %s: %v", tc.textFile, err)
			}

			jsonEntries, parsed := parseTDNFUpdateInfoJSON(string(jsonBytes))
			if !parsed {
				t.Fatalf("parseTDNFUpdateInfoJSON failed to parse a real capture (json_exit=0 in manifest)")
			}
			textEntries := parseTDNFUpdateInfoText(string(textBytes))

			jsonAdvisories := sortAdvisoriesByID(tdnfDedupeAdvisories(jsonEntries))
			textAdvisories := sortAdvisoriesByID(tdnfDedupeAdvisories(textEntries))

			if len(jsonAdvisories) != tc.wantAdvisories {
				t.Errorf("JSON path: %d advisories, want %d", len(jsonAdvisories), tc.wantAdvisories)
			}
			if len(textAdvisories) != tc.wantAdvisories {
				t.Errorf("text path: %d advisories, want %d", len(textAdvisories), tc.wantAdvisories)
			}
			for i := range jsonAdvisories {
				if i >= len(textAdvisories) {
					break
				}
				if jsonAdvisories[i].ID != textAdvisories[i].ID {
					t.Errorf("advisory[%d] ID mismatch: json=%q text=%q", i, jsonAdvisories[i].ID, textAdvisories[i].ID)
				}
			}
		})
	}
}
