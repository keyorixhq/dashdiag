package analysis

import (
	"reflect"
	"testing"

	"github.com/keyorixhq/dashdiag/internal/models"
	"github.com/keyorixhq/dashdiag/internal/testutil/resource"
)

// Resource-oracle calibration (PD1). checkNVMe's allocation is linear in the
// number of devices scored: measured 10x–23x per-input-byte amplification across
// 24 B–192 KiB (1–8192 devices). This target scores one or two devices per input,
// so allocation is a small constant and the 1 MiB AllocFloor is the active bound;
// factor 128 covers the 23x peak with headroom. Spawns no goroutines (measured
// Δ=0), no disk I/O — disk/fd oracle N/A (pure in-memory verdict).
const dv1DriveAllocFactor = 128

// FuzzDriveVerdictMonotonic — verdict-integrity fuzzing of the NVMe/SATA drive
// health verdict (checkNVMe, the live caller dispatched from heuristics.go's
// applyOne). DV1 task: the worst class of dashdiag defect is a "false OK" — the
// tool renders a drive healthy when it has NOT verified its health. The whole
// "SMART attribute / smartctl exit-bitmask" family in BUGS.md lives here
// (BUG-048 and siblings: a failing SMART drive counted as healthy; an unread
// drive defaulting to a confident OK).
//
// Where FuzzParseSMART* and the storage parser fuzzers assert "never panics",
// this asserts the VERDICT direction. Every oracle below is sound: it asserts
// ONLY a floor ("this objectively-bad reading must NOT render as a silent OK"),
// never a ceiling, so there is no false-positive direction.
//
// INVARIANT (drive verdict):
//   1. METAMORPHIC MONOTONICITY. Starting from a fixed, independently-verified
//      HEALTHY plausible drive (verdict OK), mutating ONE attribute in the
//      unambiguously-worse direction (SMART self-assessment FAILED, a
//      reallocated/pending/uncorrectable sector, a media error, a set
//      critical-warning bit) must make the verdict strictly worse — never leave
//      it OK, never improve it.
//   2. UNKNOWN IS NOT OK. A drive whose SMART was NOT read (SmartRead=false,
//      any reason) must be DISCLOSED — checkNVMe returns a non-empty insight
//      marked Unverified — never a silent empty "all drives healthy".
//   3. DETERMINISM. The same NVMeInfo yields an identical verdict.
//   4. PERMUTATION INVARIANCE. Reordering the independent per-drive entries does
//      not change the multiset of verdict levels (drive order is not semantic).
//
// What this does NOT verify (honest limits):
//   - It feeds model structs, i.e. it starts AFTER the collector parse step. It
//     proves the ANALYSIS verdict floors correctly; it does not prove the
//     collector populated those fields correctly from raw smartctl/nvme output
//     (the exit-code bitmask parsing itself is covered by disk_linux_test.go /
//     nvme_linux_test.go, separately). A false OK created purely in the parser
//     (e.g. dropping a FAILED verdict before it reaches SATADevice.SmartOK) is
//     out of this target's reach.
//   - "Healthy fixture is really healthy" is asserted for the ONE synthetic
//     baseline here, not for every real drive on every distro.
//   - It does not assert the EXACT level (CRIT vs WARN) except where the code
//     documents it; it asserts the floor "not OK".

// levelRankDV1 orders verdict levels; INFO/empty/PENDING are "OK-ish" (not a
// raised alarm). Matches render.severityOrder (CRIT>WARN>rest).
func levelRankDV1(level string) int {
	switch level {
	case "CRIT":
		return 2
	case "WARN":
		return 1
	default: // "", "OK", "INFO", "PENDING"
		return 0
	}
}

// worstLevelDV1 returns the highest raised level across insights, "" if none is
// raised (a silent OK verdict).
func worstLevelDV1(ins []models.Insight) string {
	worst := ""
	for _, in := range ins {
		if levelRankDV1(in.Level) > levelRankDV1(worst) {
			worst = in.Level
		}
	}
	return worst
}

// anyUnverified reports whether any insight is marked Unverified (surfaced, not
// a silent pass — see models.Insight.Unverified).
func anyUnverified(ins []models.Insight) bool {
	for _, in := range ins {
		if in.Unverified {
			return true
		}
	}
	return false
}

func clampInt(v, lo, hi int) int {
	if v < lo {
		return lo
	}
	if v > hi {
		return hi
	}
	return v
}

func clampInt64(v, lo, hi int64) int64 {
	if v < lo {
		return lo
	}
	if v > hi {
		return hi
	}
	return v
}

func FuzzDriveVerdictMonotonic(f *testing.F) {
	// Seeds: a clean drive, a drive with each bad attribute, an unread drive.
	f.Add(35, 100, 10, 0, 0, int64(0), true, uint8(0), 0, 0, 0, 30, true, true, uint8(0))
	f.Add(42, 100, 10, 0, 4, int64(0), true, uint8(0), 1, 0, 0, 30, true, true, uint8(0)) // nvme crit bit
	f.Add(42, 100, 10, 0, 0, int64(7), true, uint8(0), 0, 2, 0, 30, true, true, uint8(0)) // nvme media + sata pending
	f.Add(42, 100, 10, 0, 0, int64(0), false, uint8(1), 0, 0, 5, 30, false, false, uint8(2))

	f.Fuzz(func(t *testing.T,
		nvmeTemp, spare, spareThr, pctUsed, critWarn int, mediaErr int64, nvmeRead bool, nvmeUnread uint8,
		realloc, pending, uncorr, sataTemp int, smartOK, sataRead bool, sataUnread uint8,
	) {
		// ---- NVMe: build a PLAUSIBLE, scored device from clamped inputs. ----
		// Ranges chosen so nvmeSmartPlausible() is true and NVMeNoRealData() is
		// false (a real temperature plus non-sentinel fields), so the device is
		// actually scored rather than routed to an unverified path.
		nvmeTemp = clampInt(nvmeTemp, 0, 120) // plausible, reported
		spare = clampInt(spare, 20, 100)      // keep above the "low spare" WARN band
		spareThr = clampInt(spareThr, 0, 10)  // threshold below spare so no end-of-life CRIT
		pctUsed = clampInt(pctUsed, 0, 200)
		critWarn = clampInt(critWarn, 0, 0xFF)
		mediaErr = clampInt64(mediaErr, 0, 1_000_000)

		scoredNVMe := models.NVMeDevice{
			Name: "nvme0", TempC: float64(nvmeTemp), AvailableSparePct: spare,
			SpareThresholdPct: spareThr, PercentageUsed: pctUsed, CriticalWarning: critWarn,
			MediaErrors: mediaErr, PowerOnHours: 1000, PowerCycles: 10, SmartRead: true,
		}
		if !nvmeSmartPlausible(scoredNVMe) || NVMeNoRealData(scoredNVMe) {
			t.Fatalf("fixture bug: synthetic NVMe device should be plausible/scored: %+v", scoredNVMe)
		}
		// Resource oracle: bound the live checkNVMe call and record goroutine
		// growth. inputLen is a small fixed representative of the scored device
		// (all-scalar fuzz inputs); the existing monotonicity/false-OK assertions
		// below are unchanged and run outside the measured closure.
		const nvmeInputLen = 24
		var nvmeOut []models.Insight
		rr := resource.Check(t, nvmeInputLen, dv1DriveAllocFactor, func() {
			nvmeOut = checkNVMe(models.NVMeInfo{Devices: []models.NVMeDevice{scoredNVMe}})
		})
		if rr.GoroutineDiff > dv1MaxGoroutineDiff {
			t.Fatalf("goroutine growth: checkNVMe left %d extra goroutines", rr.GoroutineDiff)
		}
		// Oracle 1 (floors): a set critical-warning bit or a media error is an
		// unambiguous drive-failure signal — must raise CRIT, never a silent OK.
		if critWarn > 0 && worstLevelDV1(nvmeOut) != "CRIT" {
			t.Fatalf("FALSE-OK: NVMe critical_warning=0x%x scored %q, want CRIT; insights=%+v", critWarn, worstLevelDV1(nvmeOut), nvmeOut)
		}
		if mediaErr > 0 && worstLevelDV1(nvmeOut) != "CRIT" {
			t.Fatalf("FALSE-OK: NVMe media_errors=%d scored %q, want CRIT; insights=%+v", mediaErr, worstLevelDV1(nvmeOut), nvmeOut)
		}
		if pctUsed >= 90 && worstLevelDV1(nvmeOut) == "" {
			t.Fatalf("FALSE-OK: NVMe percentage_used=%d scored a silent OK, want at least WARN; insights=%+v", pctUsed, nvmeOut)
		}

		// Oracle 2 (unknown is not OK): an UNREAD NVMe drive must be disclosed.
		reasons := []string{"needs_root", "tool_absent", "error"}
		unreadNVMe := models.NVMeDevice{
			Name: "nvme9", SmartRead: false, SmartUnreadReason: reasons[int(nvmeUnread)%len(reasons)],
		}
		unreadOut := checkNVMe(models.NVMeInfo{Devices: []models.NVMeDevice{unreadNVMe}})
		if len(unreadOut) == 0 {
			t.Fatalf("FALSE-OK: unread NVMe drive produced NO insight (silent 'healthy'); reason=%q", unreadNVMe.SmartUnreadReason)
		}
		if !anyUnverified(unreadOut) {
			t.Fatalf("FALSE-OK: unread NVMe drive disclosed but NOT marked Unverified; insights=%+v", unreadOut)
		}

		// ---- SATA: metamorphic monotonicity from a fixed HEALTHY baseline. ----
		// healthySATA is independently healthy (verified OK in the red-proof): a
		// passing SMART self-assessment, zero error counters, cool, plausible.
		healthySATA := models.SATADevice{
			Name: "sda", Type: "sata", SmartRead: true, SmartOK: true,
			TempC: 30, PowerOnHours: 1000,
		}
		baseOut := checkNVMe(models.NVMeInfo{SATADevices: []models.SATADevice{healthySATA}})
		if worstLevelDV1(baseOut) != "" {
			t.Fatalf("fixture bug: healthy SATA baseline is not OK; insights=%+v", baseOut)
		}

		// Apply ONE fuzz-chosen worsening to the healthy baseline and assert the
		// verdict is strictly worse (never stays OK). Each field below is an
		// unambiguous "worse" direction per checkNVMe's documented scoring.
		realloc = clampInt(realloc, 0, 100_000_000)
		pending = clampInt(pending, 0, 100_000_000)
		uncorr = clampInt(uncorr, 0, 100_000_000)
		worsenings := []struct {
			name string
			dev  models.SATADevice
			bad  bool // true when this mutation is objectively worse than baseline
		}{
			{"smart-FAILED", setSATA(healthySATA, func(d *models.SATADevice) { d.SmartOK = false }), true},
			{"reallocated", setSATA(healthySATA, func(d *models.SATADevice) { d.ReallocatedSectors = realloc }), realloc > 0},
			{"pending", setSATA(healthySATA, func(d *models.SATADevice) { d.PendingSectors = pending }), pending > 0},
			{"uncorrectable", setSATA(healthySATA, func(d *models.SATADevice) { d.UncorrectableErrors = uncorr }), uncorr > 0},
		}
		for _, w := range worsenings {
			if !sataSmartPlausible(w.dev) {
				continue // mutation pushed it out of plausible range — routed to unverified, still not a false OK
			}
			out := checkNVMe(models.NVMeInfo{SATADevices: []models.SATADevice{w.dev}})
			if w.bad {
				if worstLevelDV1(out) == "" {
					t.Fatalf("MONOTONICITY: SATA worsening %q left verdict OK (false OK); dev=%+v insights=%+v", w.name, w.dev, out)
				}
				if levelRankDV1(worstLevelDV1(out)) < levelRankDV1(worstLevelDV1(baseOut)) {
					t.Fatalf("MONOTONICITY: SATA worsening %q improved verdict from %q to %q", w.name, worstLevelDV1(baseOut), worstLevelDV1(out))
				}
			}
		}

		// Oracle 2 for SATA: an unread/errored SATA drive must be disclosed.
		sReasons := []string{"needs_root", "no_smart", "error"}
		unreadSATA := models.SATADevice{Name: "sdz", Type: "sata", SmartRead: sataRead && false,
			SmartUnreadReason: sReasons[int(sataUnread)%len(sReasons)], Error: "read failed"}
		sUnreadOut := checkNVMe(models.NVMeInfo{SATADevices: []models.SATADevice{unreadSATA}})
		if len(sUnreadOut) == 0 || !anyUnverified(sUnreadOut) {
			t.Fatalf("FALSE-OK: unread/errored SATA drive not disclosed as Unverified; insights=%+v", sUnreadOut)
		}

		// Oracle 3 (determinism): identical input, identical verdict.
		info := models.NVMeInfo{Devices: []models.NVMeDevice{scoredNVMe}, SATADevices: []models.SATADevice{healthySATA}}
		if !reflect.DeepEqual(checkNVMe(info), checkNVMe(info)) {
			t.Fatalf("NON-DETERMINISM: checkNVMe gave two different verdicts for the same input")
		}

		// Oracle 4 (permutation): reordering independent drives keeps the level
		// multiset. Use two distinct scored drives so order is observable.
		d2 := scoredNVMe
		d2.Name = "nvme1"
		ab := checkNVMe(models.NVMeInfo{Devices: []models.NVMeDevice{scoredNVMe, d2}})
		ba := checkNVMe(models.NVMeInfo{Devices: []models.NVMeDevice{d2, scoredNVMe}})
		if !sameLevelMultiset(ab, ba) {
			t.Fatalf("PERMUTATION: drive order changed the verdict multiset:\n ab=%s\n ba=%s", levelsOf(ab), levelsOf(ba))
		}
	})
}

func setSATA(base models.SATADevice, mut func(*models.SATADevice)) models.SATADevice {
	d := base
	mut(&d)
	return d
}

func levelsOf(ins []models.Insight) []string {
	out := make([]string, 0, len(ins))
	for _, in := range ins {
		out = append(out, in.Level)
	}
	return out
}

func sameLevelMultiset(a, b []models.Insight) bool {
	counts := map[string]int{}
	for _, in := range a {
		counts[in.Level]++
	}
	for _, in := range b {
		counts[in.Level]--
	}
	for _, c := range counts {
		if c != 0 {
			return false
		}
	}
	return true
}
