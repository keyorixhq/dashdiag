package baseline

import (
	"testing"

	"github.com/keyorixhq/dashdiag/internal/models"
	"github.com/keyorixhq/dashdiag/internal/runner"
)

// TestBuildSnapshot_PropagatesUnverified guards the false-clean fix's baseline
// half: an Insight marked Unverified (e.g. a heuristic that downgraded to INFO
// because the data could not be measured this run) must carry that flag onto
// the CheckResult it produces, not just its Status/Value.
func TestBuildSnapshot_PropagatesUnverified(t *testing.T) {
	t.Parallel()
	results := []runner.Result{{Name: "Security", Data: models.SecurityInfo{}}}
	insights := []models.Insight{
		{Check: "Security", Level: "INFO", Message: "some checks limited — run as root", Unverified: true},
	}

	snap := BuildSnapshot(results, insights)
	if len(snap.Checks) != 1 {
		t.Fatalf("want 1 check, got %d: %+v", len(snap.Checks), snap.Checks)
	}
	if !snap.Checks[0].Unverified {
		t.Errorf("CheckResult.Unverified = false, want true (insight was Unverified)")
	}
}

// TestBuildSnapshot_WorstRankKeepsUnverifiedFlag guards that when multiple
// insights match the same check name, the Unverified flag tracks whichever
// insight was kept as the worst (not left over from a different, non-worst
// insight, and not silently dropped once a worse status wins).
func TestBuildSnapshot_WorstRankKeepsUnverifiedFlag(t *testing.T) {
	t.Parallel()
	results := []runner.Result{{Name: "Drives", Data: models.DiskInfo{}}}
	insights := []models.Insight{
		{Check: "Drives", Level: "INFO", Message: "info note", Unverified: false},
		{Check: "Drives", Level: "WARN", Message: "SMART health not read — needs root", Unverified: true},
	}

	snap := BuildSnapshot(results, insights)
	if len(snap.Checks) != 1 {
		t.Fatalf("want 1 check, got %d: %+v", len(snap.Checks), snap.Checks)
	}
	c := snap.Checks[0]
	if c.Status != "WARN" {
		t.Errorf("Status = %q, want WARN (the worst-ranked insight)", c.Status)
	}
	if !c.Unverified {
		t.Errorf("Unverified = false, want true (the worst-ranked insight, WARN, was Unverified)")
	}
}

// TestComputeDiff_UnverifiedNeverImproved is the core regression guard: a
// confirmed WARN/CRIT that becomes an Unverified INFO on the next run (e.g.
// re-run non-root, a collector that stopped being able to read a root-gated
// file) must NEVER read as Improved. Before this fix, ComputeDiff ranked
// statuses purely by string (WARN=2 > INFO=1), so this exact transition
// reported "Improved=true" — a false-clean recovery that `dsd health --diff`,
// `dsd baseline diff`, and the MCP dsd_diff tool all rendered as green/an
// improvement arrow, when the check was simply never verified this run.
func TestComputeDiff_UnverifiedNeverImproved(t *testing.T) {
	t.Parallel()
	before := &Snapshot{Checks: []CheckResult{
		{Name: "Security", Status: "WARN", Value: "sudoers NOPASSWD entry found"},
	}}
	after := &Snapshot{Checks: []CheckResult{
		{Name: "Security", Status: "INFO", Value: "some checks limited — run as root", Unverified: true},
	}}

	diffs := ComputeDiff(before, after)
	if len(diffs) != 1 {
		t.Fatalf("want 1 diff entry, got %d: %+v", len(diffs), diffs)
	}
	d := diffs[0]
	if d.Improved {
		t.Errorf("Improved = true, want false — WARN->unverified-INFO must never read as a confirmed improvement")
	}
	if !d.Unverified {
		t.Errorf("Unverified = false, want true — the After side was never actually measured this run")
	}
	if !d.Changed {
		t.Errorf("Changed = false, want true — the status text did change (WARN -> INFO)")
	}
}

// TestComputeDiff_VerifiedBecomingUnverifiedStillNotImproved covers the
// opposite status-rank direction: even a CRIT->INFO(unverified) transition —
// which under naive rank comparison looks like the single biggest possible
// "improvement" — must not be Improved.
func TestComputeDiff_VerifiedBecomingUnverifiedStillNotImproved(t *testing.T) {
	t.Parallel()
	before := &Snapshot{Checks: []CheckResult{
		{Name: "Drives", Status: "CRIT", Value: "SMART check FAILED"},
	}}
	after := &Snapshot{Checks: []CheckResult{
		{Name: "Drives", Status: "INFO", Value: "SMART health not read — needs root", Unverified: true},
	}}

	diffs := ComputeDiff(before, after)
	if len(diffs) != 1 {
		t.Fatalf("want 1 diff entry, got %d: %+v", len(diffs), diffs)
	}
	if diffs[0].Improved {
		t.Errorf("Improved = true, want false — CRIT->unverified-INFO must not read as the drive being fixed")
	}
}

// TestComputeDiff_UnverifiedBecomingVerifiedAlsoNotImproved covers the
// reverse direction: a prior Unverified INFO that is now a confirmed OK is
// new information (we can finally see it), not a verified improvement over a
// previously-known-bad state — there is no baseline evidence it was ever bad.
func TestComputeDiff_UnverifiedBecomingVerifiedAlsoNotImproved(t *testing.T) {
	t.Parallel()
	before := &Snapshot{Checks: []CheckResult{
		{Name: "Security", Status: "INFO", Value: "some checks limited — run as root", Unverified: true},
	}}
	after := &Snapshot{Checks: []CheckResult{
		{Name: "Security", Status: "OK", Value: ""},
	}}

	diffs := ComputeDiff(before, after)
	if len(diffs) != 1 {
		t.Fatalf("want 1 diff entry, got %d: %+v", len(diffs), diffs)
	}
	d := diffs[0]
	if d.Improved {
		t.Errorf("Improved = true, want false — unverified-INFO->OK is newly-confirmed information, not a verified recovery")
	}
	if !d.Unverified {
		t.Errorf("Unverified = false, want true — the Before side was never actually measured")
	}
}

// TestComputeDiff_GenuineImprovementStillWorks is the contrast case: a
// verified WARN that becomes a verified OK (neither side Unverified) must
// still report Improved=true — the fix must not make ComputeDiff overly
// conservative and hide real, confirmed improvements.
func TestComputeDiff_GenuineImprovementStillWorks(t *testing.T) {
	t.Parallel()
	before := &Snapshot{Checks: []CheckResult{
		{Name: "Disk", Status: "WARN", Value: "disk 90% full"},
	}}
	after := &Snapshot{Checks: []CheckResult{
		{Name: "Disk", Status: "OK", Value: ""},
	}}

	diffs := ComputeDiff(before, after)
	if len(diffs) != 1 {
		t.Fatalf("want 1 diff entry, got %d: %+v", len(diffs), diffs)
	}
	d := diffs[0]
	if !d.Improved {
		t.Errorf("Improved = false, want true — a fully verified WARN->OK is a real, confirmed improvement")
	}
	if d.Unverified {
		t.Errorf("Unverified = true, want false — neither side of this transition was unverified")
	}
}
