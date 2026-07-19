//go:build !windows

package cis

import (
	"testing"

	"github.com/keyorixhq/dashdiag/internal/models"
)

func TestBSIMappingRuleIDsExist(t *testing.T) {
	t.Parallel()
	ruleSet := make(map[string]bool, len(CISRules))
	for _, r := range CISRules {
		ruleSet[r.ID] = true
	}
	for cisID := range bsiMapping {
		if !ruleSet[cisID] {
			t.Errorf("bsiMapping key %q does not exist in CISRules", cisID)
		}
	}
}

func TestBSIRequirementCoverage(t *testing.T) {
	t.Parallel()
	// Build a set of all requirement IDs that appear in bsiMapping values.
	covered := make(map[string]int)
	for _, refs := range bsiMapping {
		for _, ref := range refs {
			covered[ref]++
		}
	}
	// Requirements known to be UNMAPPED (no CIS OS-level equivalent).
	unmapped := map[string]bool{
		"SYS.1.3.A16": true,
		"SYS.1.3.A17": true,
		"SYS.1.1.A9":  true,
		"SYS.1.1.A33": true,
		"SYS.1.1.A34": true,
		"SYS.1.1.A36": true,
	}
	for _, baustein := range BSIBausteine {
		for _, req := range baustein.Requirements {
			if unmapped[req.ID] {
				if covered[req.ID] > 0 {
					t.Errorf("%s is declared UNMAPPED but has %d mapping(s)", req.ID, covered[req.ID])
				}
				continue
			}
			if covered[req.ID] < 1 {
				t.Errorf("%s should have ≥1 CIS rule mapped but has none", req.ID)
			}
		}
	}
}

func TestBSIGroupByBSI(t *testing.T) {
	t.Parallel()
	// Synthetic: one PASS and one FAIL result each mapped to a different requirement.
	results := []models.CISResult{
		{ID: "6.2.5", Status: models.CISPass, BSIRefs: []string{"SYS.1.3.A2"}},
		{ID: "5.3.2", Status: models.CISFail, BSIRefs: []string{"SYS.1.3.A6"}},
	}
	groups := GroupByBSI(results)
	// Count total requirements expected.
	total := 0
	for _, b := range BSIBausteine {
		total += len(b.Requirements)
	}
	if len(groups) != total {
		t.Fatalf("GroupByBSI returned %d groups, want %d", len(groups), total)
	}
	// Check that each group has the correct Baustein back-reference.
	for _, g := range groups {
		found := false
		for _, b := range BSIBausteine {
			if b.ID == g.Baustein.ID {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("group %s has unknown Baustein %q", g.Req.ID, g.Baustein.ID)
		}
	}
}

func TestBSIGroupStatusDerivation(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name    string
		results []models.CISResult
		want    string
	}{
		{
			name: "all pass → PASS",
			results: []models.CISResult{
				{ID: "6.2.5", Status: models.CISPass, BSIRefs: []string{"SYS.1.3.A2"}},
				{ID: "6.2.6", Status: models.CISPass, BSIRefs: []string{"SYS.1.3.A2"}},
			},
			want: "PASS",
		},
		{
			name: "all fail → FAIL",
			results: []models.CISResult{
				{ID: "6.2.5", Status: models.CISFail, BSIRefs: []string{"SYS.1.3.A2"}},
			},
			want: "FAIL",
		},
		{
			name: "mix pass+fail → PARTIAL",
			results: []models.CISResult{
				{ID: "6.2.5", Status: models.CISPass, BSIRefs: []string{"SYS.1.3.A2"}},
				{ID: "6.2.6", Status: models.CISFail, BSIRefs: []string{"SYS.1.3.A2"}},
			},
			want: "PARTIAL",
		},
		{
			name: "all skip → SKIP",
			results: []models.CISResult{
				{ID: "6.2.5", Status: models.CISSkipped, BSIRefs: []string{"SYS.1.3.A2"}},
			},
			want: "SKIP",
		},
		{
			name: "no results → UNMAPPED",
			results: []models.CISResult{},
			want:    "UNMAPPED",
		},
	}
	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			groups := GroupByBSI(tc.results)
			// Find SYS.1.3.A2 group.
			for _, g := range groups {
				if g.Req.ID == "SYS.1.3.A2" {
					if g.Status != tc.want {
						t.Errorf("SYS.1.3.A2 status = %q, want %q", g.Status, tc.want)
					}
					return
				}
			}
			t.Fatal("SYS.1.3.A2 group not found")
		})
	}
}

func TestBSIRefsLookup(t *testing.T) {
	t.Parallel()
	tests := []struct {
		cisID   string
		wantAny string // one expected ref
	}{
		{"6.2.5", "SYS.1.3.A2"},
		{"5.2.10", "SYS.1.3.A8"},
		{"1.3.1", "SYS.1.3.A5"},
		{"1.3.1", "SYS.1.1.A27"},
		{"3.5.1", "SYS.1.1.A19"},
		{"2.1.1", "OPS.1.1.5.A4"},
		{"1.2.4", "OPS.1.1.3.A3"},
	}
	for _, tc := range tests {
		tc := tc
		t.Run(tc.cisID+"→"+tc.wantAny, func(t *testing.T) {
			t.Parallel()
			refs := BSIRefs(tc.cisID)
			found := false
			for _, r := range refs {
				if r == tc.wantAny {
					found = true
					break
				}
			}
			if !found {
				t.Errorf("BSIRefs(%q) = %v, want it to contain %q", tc.cisID, refs, tc.wantAny)
			}
		})
	}
}

func TestBSIUnknownRuleReturnsNil(t *testing.T) {
	t.Parallel()
	if got := BSIRefs("99.99.99"); got != nil {
		t.Errorf("BSIRefs(unknown) = %v, want nil", got)
	}
}

func TestBSIBausteineOrdering(t *testing.T) {
	t.Parallel()
	// Verify the declaration order: SYS.1.3 first, then SYS.1.1, then OPS.1.1.
	if len(BSIBausteine) < 3 {
		t.Fatalf("expected at least 3 BSIBausteine, got %d", len(BSIBausteine))
	}
	if BSIBausteine[0].ID != "SYS.1.3" {
		t.Errorf("BSIBausteine[0].ID = %q, want SYS.1.3", BSIBausteine[0].ID)
	}
	if BSIBausteine[1].ID != "SYS.1.1" {
		t.Errorf("BSIBausteine[1].ID = %q, want SYS.1.1", BSIBausteine[1].ID)
	}
	if BSIBausteine[2].ID != "OPS.1.1" {
		t.Errorf("BSIBausteine[2].ID = %q, want OPS.1.1", BSIBausteine[2].ID)
	}
}
