//go:build !windows

package cis

import (
	"testing"

	"github.com/keyorixhq/dashdiag/internal/models"
)

// TestNIS2MappingRuleIDsExist verifies every key in nis2Mapping corresponds to
// a real rule in CISRules (populated by init() via buildRules()).
func TestNIS2MappingRuleIDsExist(t *testing.T) {
	t.Parallel()

	ruleIDs := make(map[string]struct{}, len(CISRules))
	for _, r := range CISRules {
		ruleIDs[r.ID] = struct{}{}
	}

	for mappedID := range nis2Mapping {
		if _, ok := ruleIDs[mappedID]; !ok {
			t.Errorf("nis2Mapping key %q has no corresponding rule in CISRules", mappedID)
		}
	}
}

// TestNIS2ArticleCoverage checks that mapped articles have sufficient rule
// counts, and that the three policy-only articles have zero OS-level mappings.
func TestNIS2ArticleCoverage(t *testing.T) {
	t.Parallel()

	// Count distinct rule IDs that map to each article.
	counts := make(map[string]int)
	for ruleID, articles := range nis2Mapping {
		seen := make(map[string]struct{})
		for _, art := range articles {
			if _, already := seen[art]; !already {
				seen[art] = struct{}{}
				counts[art]++
			}
		}
		_ = ruleID
	}

	mustHave := []string{
		"Art.21(2)(b)",
		"Art.21(2)(d)",
		"Art.21(2)(e)",
		"Art.21(2)(g)",
		"Art.21(2)(h)",
		"Art.21(2)(i)",
		"Art.21(2)(j)",
	}
	for _, art := range mustHave {
		c := counts[art]
		if c < 3 {
			t.Errorf("article %s has %d mapped rules, want >= 3", art, c)
		}
	}

	unmapped := []string{"Art.21(2)(a)", "Art.21(2)(c)", "Art.21(2)(f)"}
	for _, art := range unmapped {
		if c := counts[art]; c != 0 {
			t.Errorf("article %s expected 0 mapped rules, got %d", art, c)
		}
	}
}

// TestNIS2GroupByNIS2 exercises GroupByNIS2 with a synthetic result set.
func TestNIS2GroupByNIS2(t *testing.T) {
	t.Parallel()

	results := []models.CISResult{
		{ID: "r1", NIS2Refs: []string{"Art.21(2)(b)"}, Status: models.CISPass},
		{ID: "r2", NIS2Refs: []string{"Art.21(2)(b)"}, Status: models.CISFail},
		{ID: "r3", NIS2Refs: []string{"Art.21(2)(g)"}, Status: models.CISPass},
		{ID: "r4", NIS2Refs: []string{"Art.21(2)(g)"}, Status: models.CISPass},
		{ID: "r5", NIS2Refs: []string{}, Status: models.CISPass}, // unmapped
	}

	groups := GroupByNIS2(results)

	if got := len(groups); got != len(NIS2Articles) {
		t.Fatalf("GroupByNIS2 returned %d groups, want %d", got, len(NIS2Articles))
	}
	if len(NIS2Articles) != 10 {
		t.Fatalf("NIS2Articles has %d entries, want 10", len(NIS2Articles))
	}

	byID := make(map[string]NIS2ArticleGroup, len(groups))
	for _, g := range groups {
		byID[g.Article.ID] = g
	}

	t.Run("Art21_2_b_PARTIAL", func(t *testing.T) {
		t.Parallel()
		g, ok := byID["Art.21(2)(b)"]
		if !ok {
			t.Fatal("group for Art.21(2)(b) not found")
		}
		if g.Status != "PARTIAL" {
			t.Errorf("Art.21(2)(b) Status = %q, want PARTIAL", g.Status)
		}
		if g.Pass != 1 {
			t.Errorf("Art.21(2)(b) Pass = %d, want 1", g.Pass)
		}
		if g.Fail != 1 {
			t.Errorf("Art.21(2)(b) Fail = %d, want 1", g.Fail)
		}
	})

	t.Run("Art21_2_g_PASS", func(t *testing.T) {
		t.Parallel()
		g, ok := byID["Art.21(2)(g)"]
		if !ok {
			t.Fatal("group for Art.21(2)(g) not found")
		}
		if g.Status != "PASS" {
			t.Errorf("Art.21(2)(g) Status = %q, want PASS", g.Status)
		}
		if g.Pass != 2 {
			t.Errorf("Art.21(2)(g) Pass = %d, want 2", g.Pass)
		}
		if g.Fail != 0 {
			t.Errorf("Art.21(2)(g) Fail = %d, want 0", g.Fail)
		}
	})

	t.Run("Art21_2_a_UNMAPPED", func(t *testing.T) {
		t.Parallel()
		g, ok := byID["Art.21(2)(a)"]
		if !ok {
			t.Fatal("group for Art.21(2)(a) not found")
		}
		if g.Status != "UNMAPPED" {
			t.Errorf("Art.21(2)(a) Status = %q, want UNMAPPED", g.Status)
		}
		if len(g.Results) != 0 {
			t.Errorf("Art.21(2)(a) len(Results) = %d, want 0", len(g.Results))
		}
	})
}

// TestNIS2ArticleGroupStatusDerivation tests status derivation for all cases.
func TestNIS2ArticleGroupStatusDerivation(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name    string
		results []models.CISResult
		want    string
	}{
		{
			name: "all_PASS",
			results: []models.CISResult{
				{NIS2Refs: []string{"Art.21(2)(b)"}, Status: models.CISPass},
				{NIS2Refs: []string{"Art.21(2)(b)"}, Status: models.CISPass},
			},
			want: "PASS",
		},
		{
			name: "all_FAIL",
			results: []models.CISResult{
				{NIS2Refs: []string{"Art.21(2)(b)"}, Status: models.CISFail},
				{NIS2Refs: []string{"Art.21(2)(b)"}, Status: models.CISFail},
			},
			want: "FAIL",
		},
		{
			name: "mix_PASS_FAIL",
			results: []models.CISResult{
				{NIS2Refs: []string{"Art.21(2)(b)"}, Status: models.CISPass},
				{NIS2Refs: []string{"Art.21(2)(b)"}, Status: models.CISFail},
			},
			want: "PARTIAL",
		},
		{
			name: "all_SKIP",
			results: []models.CISResult{
				{NIS2Refs: []string{"Art.21(2)(b)"}, Status: models.CISSkipped},
				{NIS2Refs: []string{"Art.21(2)(b)"}, Status: models.CISSkipped},
			},
			want: "SKIP",
		},
		{
			name:    "no_results",
			results: []models.CISResult{},
			want:    "UNMAPPED",
		},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			groups := GroupByNIS2(tc.results)
			byID := make(map[string]NIS2ArticleGroup, len(groups))
			for _, g := range groups {
				byID[g.Article.ID] = g
			}
			g, ok := byID["Art.21(2)(b)"]
			if !ok {
				t.Fatal("group for Art.21(2)(b) not found")
			}
			if g.Status != tc.want {
				t.Errorf("status = %q, want %q", g.Status, tc.want)
			}
		})
	}
}

// TestNIS2RefsLookup verifies NIS2Refs for known and unknown rule IDs.
func TestNIS2RefsLookup(t *testing.T) {
	t.Parallel()

	cases := []struct {
		ruleID      string
		wantNil     bool
		mustContain string
	}{
		{"4.1.3", false, "Art.21(2)(b)"},
		{"5.2.3", false, "Art.21(2)(h)"},
		{"5.2.20", false, "Art.21(2)(j)"},
		{"6.1.1", false, "Art.21(2)(i)"},
		{"999.9.9", true, ""},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.ruleID, func(t *testing.T) {
			t.Parallel()
			refs := NIS2Refs(tc.ruleID)
			if tc.wantNil {
				if refs != nil {
					t.Errorf("NIS2Refs(%q) = %v, want nil", tc.ruleID, refs)
				}
				return
			}
			if len(refs) == 0 {
				t.Fatalf("NIS2Refs(%q) returned empty slice, want non-empty", tc.ruleID)
			}
			found := false
			for _, r := range refs {
				if r == tc.mustContain {
					found = true
					break
				}
			}
			if !found {
				t.Errorf("NIS2Refs(%q) = %v, want slice containing %q", tc.ruleID, refs, tc.mustContain)
			}
		})
	}
}

// TestNIS2ArticleByID exercises NIS2ArticleByID for known and unknown IDs.
func TestNIS2ArticleByID(t *testing.T) {
	t.Parallel()

	t.Run("b_incident_handling", func(t *testing.T) {
		t.Parallel()
		art, ok := NIS2ArticleByID("Art.21(2)(b)")
		if !ok {
			t.Fatal("NIS2ArticleByID(Art.21(2)(b)) returned false")
		}
		if art.Title != "Incident handling" {
			t.Errorf("Title = %q, want %q", art.Title, "Incident handling")
		}
	})

	t.Run("j_secured_communications", func(t *testing.T) {
		t.Parallel()
		art, ok := NIS2ArticleByID("Art.21(2)(j)")
		if !ok {
			t.Fatal("NIS2ArticleByID(Art.21(2)(j)) returned false")
		}
		if art.Title != "Secured communications" {
			t.Errorf("Title = %q, want %q", art.Title, "Secured communications")
		}
	})

	t.Run("unknown_id", func(t *testing.T) {
		t.Parallel()
		_, ok := NIS2ArticleByID("Art.21(2)(z)")
		if ok {
			t.Error("NIS2ArticleByID(Art.21(2)(z)) returned true, want false")
		}
	})
}
