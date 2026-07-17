package cmd

import (
	"fmt"
	"strings"
	"testing"

	"github.com/keyorixhq/dashdiag/internal/baseline"
)

// TestFleetConsequenceLine_MissingBranches directly exercises the branches in
// fleetConsequenceLine that aren't reached via the fleetConsequences path:
// the WARN branch for each category that has a corresponding CRIT test, and the
// default (unknown category) branches for both CRIT and WARN.
func TestFleetConsequenceLine_MissingBranches(t *testing.T) {
	t.Parallel()
	cases := []struct {
		cat, level string
		contains   string
	}{
		// WARN branches suppressed by CRIT in existing tests
		{"storage", "WARN", "storage issues"},
		{"patches", "WARN", "pending security patches"},
		{"services", "WARN", "service reliability"},
		{"network", "WARN", "network configuration"},
		{"compute", "WARN", "compute resource pressure"},
		// default (unknown category) branches
		{"other", "CRIT", "critical issues"},
		{"other", "WARN", "requiring review"},
	}
	for _, tc := range cases {
		t.Run(tc.cat+"_"+tc.level, func(t *testing.T) {
			t.Parallel()
			got := fleetConsequenceLine(tc.cat, tc.level, 2, 5)
			if !strings.Contains(got, tc.contains) {
				t.Errorf("fleetConsequenceLine(%q, %q, 2, 5) = %q, want contains %q",
					tc.cat, tc.level, got, tc.contains)
			}
		})
	}
}

// TestWaveConsequences_LoadErrorWithOtherCategory covers the
// `entries[i].cat == "load-error"` sort comparator branch inside waveConsequences.
// When only one entry exists (load-error alone), the comparator is never called.
// Here we add a second category (driver regression) so the sort runs with two
// entries, triggering the "load-error goes first" return-true path.
func TestWaveConsequences_LoadErrorWithOtherCategory(t *testing.T) {
	t.Parallel()
	results := []waveResult{
		{
			Pair:    wavePair{Src: "vm01", Dst: "dst01"},
			Verdict: certFail,
			Err:     fmt.Errorf("bundle not found"),
		},
		{
			Pair:    wavePair{Src: "vm02", Dst: "dst02"},
			Verdict: certFail,
			Regressions: []baseline.DiffEntry{
				{Name: "vmware-nic", Before: "ok", After: "degraded"},
			},
		},
	}
	bullets := waveConsequences(results)
	if len(bullets) == 0 {
		t.Fatal("expected at least one bullet for load-error + driver regression")
	}
	// load-error bullet must be first (sort comparator puts it first).
	if !strings.Contains(bullets[0], "bundle load") {
		t.Errorf("load-error should produce the first bullet, got: %q", bullets[0])
	}
}
