package cmd

import (
	"fmt"
	"strings"
	"testing"

	"github.com/keyorixhq/dashdiag/internal/baseline"
)

// TestWaveConsequenceLine_AllCases directly exercises every switch branch in
// waveConsequenceLine. TestWaveConsequences_MaxFiveBullets caps at 5 bullets
// from 6 categories, nondeterministically dropping one call — so at least
// "storage", "security", and "memory" need a direct exercise to guarantee
// they are always covered.
func TestWaveConsequenceLine_AllCases(t *testing.T) {
	t.Parallel()
	cases := []struct {
		cat  string
		want string
	}{
		{"driver", "paravirtual performance"},
		{"cloud-init", "first-boot provisioning"},
		{"storage", "storage or filesystem"},
		{"services", "service failures"},
		{"security", "security posture"},
		{"memory", "memory or swap"},
		{"load-error", "bundle load"},
		{"other", "requiring remediation"},
	}
	for _, tc := range cases {
		t.Run(tc.cat, func(t *testing.T) {
			t.Parallel()
			got := waveConsequenceLine(tc.cat, 2, 5)
			if !strings.Contains(got, tc.want) {
				t.Errorf("waveConsequenceLine(%q) = %q, want contains %q", tc.cat, got, tc.want)
			}
		})
	}
}

// TestFleetConsequenceLine_MissingBranches directly exercises the branches in
// fleetConsequenceLine that aren't reached via the fleetConsequences path:
// WARN branches (suppressed by CRIT in fleetConsequences dedup), CRIT branches
// that may be dropped by the nondeterministic 5-bullet cap, and the default
// (unknown category) branches.
func TestFleetConsequenceLine_MissingBranches(t *testing.T) {
	t.Parallel()
	cases := []struct {
		cat, level string
		contains   string
	}{
		// WARN branches suppressed by CRIT in existing tests
		{"storage", "WARN", "storage issues"},
		{"memory", "WARN", "elevated memory pressure"},
		{"patches", "WARN", "pending security patches"},
		{"services", "WARN", "service reliability"},
		{"network", "WARN", "network configuration"},
		{"compute", "WARN", "compute resource pressure"},
		// CRIT branches that may be dropped by the nondeterministic 5-bullet cap
		{"storage", "CRIT", "immediate storage failure"},
		{"memory", "CRIT", "critical memory pressure"},
		{"patches", "CRIT", "unpatched vulnerabilities"},
		{"services", "CRIT", "failed or crashing"},
		{"network", "CRIT", "connectivity faults"},
		{"compute", "CRIT", "resource exhaustion"},
		// security has no level check — any level exercises the single return
		{"security", "WARN", "security hardening gaps"},
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

// TestWaveConsequences_LoadErrorWithOtherCategory covers two branches:
//  1. The `entries[i].cat == "load-error"` sort comparator — only fires when
//     there are 2+ entries, so a second category (here "other") is needed.
//  2. The `default` branch of waveConsequenceLine — reached via the "other"
//     category, which waveRegressionCategory returns for unrecognised names.
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
				// "uptime" matches none of the substrings in waveRegressionCategory
				// → returns "other" → hits default branch of waveConsequenceLine.
				{Name: "uptime", Before: "99%", After: "87%"},
			},
		},
	}
	bullets := waveConsequences(results)
	if len(bullets) < 2 {
		t.Fatalf("expected at least 2 bullets (load-error + other), got %d: %v", len(bullets), bullets)
	}
	// load-error bullet must be first (sort comparator puts it first).
	if !strings.Contains(bullets[0], "bundle load") {
		t.Errorf("first bullet should be load-error, got: %q", bullets[0])
	}
	// "other" category falls to waveConsequenceLine default branch.
	if !strings.Contains(bullets[1], "requiring remediation") {
		t.Errorf("second bullet should be the 'other' default, got: %q", bullets[1])
	}
}

// TestWaveConsequenceLine_ServicesCaseAndSortComparator covers two
// nondeterministically-missed paths:
//  1. waveConsequenceLine "services" case: a regression named "systemd-resolved"
//     maps to the services category.
//  2. waveConsequences sort comparator `entries[i].count > entries[j].count` path:
//     triggered when the entry at index i is NOT "load-error" and we fall through
//     to the count comparison.  We need ≥2 non-load-error entries; services and
//     cloud-init (count 2 vs count 1) force the comparator to reach that line.
func TestWaveConsequenceLine_ServicesCaseAndSortComparator(t *testing.T) {
	t.Parallel()
	results := []waveResult{
		{
			Pair:    wavePair{Src: "vm01", Dst: "dst01"},
			Verdict: certFail,
			Regressions: []baseline.DiffEntry{
				// "systemd-resolved" → services category
				{Name: "systemd-resolved", Before: "OK", After: "CRIT"},
			},
		},
		{
			Pair:    wavePair{Src: "vm02", Dst: "dst02"},
			Verdict: certFail,
			Regressions: []baseline.DiffEntry{
				// Second entry with services regression: count → 2
				{Name: "systemd-networkd", Before: "OK", After: "WARN"},
				// cloud-init entry (count → 1) so count comparison fires
				{Name: "cloud-init", Before: "OK", After: "CRIT"},
			},
		},
	}
	bullets := waveConsequences(results)
	if len(bullets) == 0 {
		t.Fatal("expected at least one bullet for services + cloud-init regressions")
	}
	found := false
	for _, b := range bullets {
		if strings.Contains(b, "service failures") {
			found = true
		}
	}
	if !found {
		t.Errorf("expected a 'service failures' bullet for services regressions, got: %v", bullets)
	}
}
