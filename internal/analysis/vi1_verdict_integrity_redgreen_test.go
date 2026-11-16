package analysis

// VI1 red/green proofs. "A guard nobody has watched fail is not a guard."
// Each oracle used by the generator (monotonicity, false-OK, order-independence,
// idempotence) is watched FAILING on a deliberately-broken local check function
// and PASSING on a correct one. The broken functions live only here (never in
// verdictChecks or any production path), so these proofs are committed and run
// on every `go test` — the oracle itself is the thing under test, not the
// product.

import (
	"testing"

	"github.com/keyorixhq/dashdiag/internal/models"
)

// --- (a) monotonicity oracle -----------------------------------------------

// brokenMonotone IMPROVES the verdict when the metric worsens: OK below 90, but
// above 95 it drops back to a silent OK instead of staying CRIT. A correct
// verdict never does this.
func brokenMonotone(usedPct float64) []models.Insight {
	switch {
	case usedPct >= 95:
		return nil // BUG: worst input reads as clean
	case usedPct >= 90:
		return []models.Insight{{Level: "CRIT", Check: "x", Message: "full"}}
	default:
		return nil
	}
}

func goodMonotone(usedPct float64) []models.Insight {
	if usedPct >= 90 {
		return []models.Insight{{Level: "CRIT", Check: "x", Message: "full"}}
	}
	return nil
}

// monotonicityHolds is the oracle in isolation: worsening (raising usedPct) must
// never lower the rank.
func monotonicityHolds(run func(float64) []models.Insight) bool {
	for base := 0.0; base <= 100; base += 1 {
		baseRank := verdictRank(run(base))
		for _, delta := range []float64{1, 5, 10, 40} {
			if verdictRank(run(base+delta)) < baseRank {
				return false
			}
		}
	}
	return true
}

func TestVI1MonotonicityOracleRedGreen(t *testing.T) {
	if monotonicityHolds(brokenMonotone) {
		t.Fatal("RED FAIL: monotonicity oracle did NOT catch a verdict that improves when the metric worsens")
	}
	if !monotonicityHolds(goodMonotone) {
		t.Fatal("GREEN FAIL: monotonicity oracle wrongly flagged a correct monotone verdict")
	}
}

// --- (b) false-OK oracle ---------------------------------------------------

// brokenFalseOK returns a silent OK (nil) on a measurement gap — the false-clean
// bug. goodFalseOK discloses it as Unverified.
func brokenFalseOK(gap bool) []models.Insight {
	if gap {
		return nil // BUG: unmeasured reads as clean
	}
	return nil
}

func goodFalseOK(gap bool) []models.Insight {
	if gap {
		return []models.Insight{unverifiedInsight(models.ReasonUnreadable, "INFO", "x", "could not measure", nil)}
	}
	return nil
}

// falseOKHeld reports whether a gap input produced a disclosed Unverified
// insight (true == oracle satisfied).
func falseOKHeld(run func(bool) []models.Insight) bool {
	out := run(true)
	return len(out) > 0 && vi1HasUnverified(out)
}

func TestVI1FalseOKOracleRedGreen(t *testing.T) {
	if falseOKHeld(brokenFalseOK) {
		t.Fatal("RED FAIL: false-OK oracle did NOT catch a silent OK on a measurement gap")
	}
	if !falseOKHeld(goodFalseOK) {
		t.Fatal("GREEN FAIL: false-OK oracle wrongly flagged a correctly-disclosed gap")
	}
}

// --- (c) order-independence oracle -----------------------------------------

// brokenOrder keeps only the FIRST item's insight (order-sensitive). goodOrder
// emits one insight per bad item regardless of order.
func brokenOrder(items []int) []models.Insight {
	var out []models.Insight
	for i, v := range items {
		if v > 0 && i == 0 { // BUG: only the first slot is scored
			out = append(out, models.Insight{Level: "WARN", Check: "x", Message: "bad"})
		}
	}
	return out
}

func goodOrder(items []int) []models.Insight {
	var out []models.Insight
	for _, v := range items {
		if v > 0 {
			out = append(out, models.Insight{Level: "WARN", Check: "x", Message: "bad"})
		}
	}
	return out
}

func orderIndependent(run func([]int) []models.Insight, items []int) bool {
	base := insightMultiset(run(items))
	rev := append([]int(nil), items...)
	for i, j := 0, len(rev)-1; i < j; i, j = i+1, j-1 {
		rev[i], rev[j] = rev[j], rev[i]
	}
	got := insightMultiset(run(rev))
	if len(base) != len(got) {
		return false
	}
	for i := range base {
		if base[i] != got[i] {
			return false
		}
	}
	return true
}

func TestVI1OrderOracleRedGreen(t *testing.T) {
	items := []int{1, 0, 0} // only the first slot is bad; reversing moves it to the last slot
	if orderIndependent(brokenOrder, items) {
		t.Fatal("RED FAIL: order oracle did NOT catch an order-dependent aggregation")
	}
	if !orderIndependent(goodOrder, items) {
		t.Fatal("GREEN FAIL: order oracle wrongly flagged an order-free aggregation")
	}
}
