package analysis

import (
	"reflect"
	"strings"
	"testing"

	"github.com/keyorixhq/dashdiag/internal/models"
	"github.com/keyorixhq/dashdiag/internal/testutil/resource"
)

// Resource-oracle calibration (PD1). checkCloudInit's allocation is linear in the
// fuzzed strings (status/extStatus/datasource/errMsg), measured at 2.1x–13.3x
// amplification across 53 B–192 KiB inputs (peak ~13x at the smallest input where
// fixed per-call overhead dominates); it falls to ~2x as the strings grow. factor
// 64 covers that with ~5x headroom and still trips any super-linear blow-up. For
// the common tiny-input case the 1 MiB AllocFloor is the active bound; the factor
// bites only once an input exceeds ~16 KiB. The function spawns no goroutines
// (measured Δ=0) and does no disk I/O, so the goroutine delta is asserted against
// a generous ceiling and the disk/fd oracle is N/A (pure in-memory verdict).
const (
	dv1CloudInitAllocFactor = 64
	dv1MaxGoroutineDiff     = 8
)

// FuzzCloudInitVerdictFalseOK — verdict-integrity fuzzing of checkCloudInit (the
// live caller dispatched from heuristics.go's applyOne). DV1 task: one of the
// 14 real "false OK" defects in BUGS.md is "a failed cloud-init shown green" —
// an instance that booted but never finished provisioning rendered as healthy.
//
// INVARIANT (cloud-init verdict):
//  1. FAILED IS NOT OK. An available cloud-init whose status is "error" OR
//     which carries any fatal error string must raise CRIT — never a silent OK.
//     (This is the exact regressed false OK.)
//  2. DEGRADED IS NOT OK. "degraded" extended-status or any recoverable error
//     must raise at least WARN.
//  3. UNKNOWN IS NOT OK. cloud-init present but its status could not be read
//     (StatusUnverified) must be DISCLOSED (non-empty, marked Unverified) —
//     never a silent empty pass.
//  4. DETERMINISM. The same CloudInitInfo yields an identical verdict.
//
// Every assertion is a sound floor (bad state => at least this severity), not a
// ceiling, so there is no false-positive direction.
//
// What this does NOT verify (honest limits):
//   - It starts from the CloudInitInfo model, i.e. after the collector parsed
//     `cloud-init status --format=json`. It proves the verdict floors on a
//     given parsed state; it does not prove the collector maps a real failed
//     cloud-init status.json onto Status=="error"/Errors (that mapping lives in
//     collectors/cloudinit_linux.go and is not exercised here).
//   - It does not assert that a genuinely-done cloud-init renders OK on every
//     cloud-init version/datasource — only the direction for the bad states.
func FuzzCloudInitVerdictFalseOK(f *testing.F) {
	f.Add(true, "error", "", "", "boom", false, false, false)
	f.Add(true, "done", "degraded done", "ec2", "", true, false, false)
	f.Add(true, "", "", "nocloud", "", false, true, true)
	f.Add(true, "done", "done", "gce", "", false, false, true)
	f.Add(false, "error", "", "", "boom", false, false, false) // not available => silent is correct
	f.Add(true, "running", "", "openstack", "", false, false, true)

	f.Fuzz(func(t *testing.T,
		available bool, status, extStatus, datasource, errMsg string,
		recoverable, statusUnverified, done bool,
	) {
		c := models.CloudInitInfo{
			Available:        available,
			Status:           status,
			ExtendedStatus:   extStatus,
			Datasource:       datasource,
			StatusUnverified: statusUnverified,
		}
		if errMsg != "" {
			c.Errors = []string{errMsg}
		}
		if recoverable {
			c.RecoverableErrors = []string{"minor: " + errMsg}
		}

		// Resource oracle: bound the allocation/time of the live verdict call and
		// record its goroutine growth. The existing false-OK assertions below are
		// unchanged and run OUTSIDE this closure, so the budget reflects only the
		// production checkCloudInit path.
		n := len(status) + len(extStatus) + len(datasource) + len(errMsg)
		var out []models.Insight
		rr := resource.Check(t, n, dv1CloudInitAllocFactor, func() {
			out = checkCloudInit(c)
		})
		if rr.GoroutineDiff > dv1MaxGoroutineDiff {
			t.Fatalf("goroutine growth: checkCloudInit left %d extra goroutines (input=%d B)", rr.GoroutineDiff, n)
		}

		if !available {
			// Not present => nothing to verify, a silent (nil) verdict is correct.
			if len(out) != 0 {
				t.Fatalf("checkCloudInit emitted insights for an unavailable cloud-init: %+v", out)
			}
			return
		}

		// Oracle 3: unknown status must be disclosed and never a silent OK. This
		// is evaluated first because the production code returns early on it.
		if c.StatusUnverified {
			if len(out) == 0 || !anyUnverified(out) {
				t.Fatalf("FALSE-OK: StatusUnverified cloud-init not disclosed as Unverified; insights=%+v", out)
			}
			return
		}

		// Oracle 1: failed cloud-init must be CRIT (the regressed false OK).
		if c.Status == "error" || len(c.Errors) > 0 {
			if worstLevelDV1(out) != "CRIT" {
				t.Fatalf("FALSE-OK: failed cloud-init (status=%q errors=%v) scored %q, want CRIT; insights=%+v",
					c.Status, c.Errors, worstLevelDV1(out), out)
			}
			return
		}

		// Oracle 2: degraded / recoverable errors must be at least WARN.
		if strings.Contains(c.ExtendedStatus, "degraded") || len(c.RecoverableErrors) > 0 {
			if levelRankDV1(worstLevelDV1(out)) < levelRankDV1("WARN") {
				t.Fatalf("FALSE-OK: degraded cloud-init (ext=%q recoverable=%v) scored %q, want >=WARN; insights=%+v",
					c.ExtendedStatus, c.RecoverableErrors, worstLevelDV1(out), out)
			}
		}

		// Oracle 4: determinism.
		if !reflect.DeepEqual(checkCloudInit(c), checkCloudInit(c)) {
			t.Fatalf("NON-DETERMINISM: checkCloudInit gave two different verdicts for the same input")
		}
	})
}
