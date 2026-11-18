package analysis

import (
	"math"
	"reflect"
	"testing"

	"github.com/keyorixhq/dashdiag/internal/models"
	"github.com/keyorixhq/dashdiag/internal/testutil/resource"
)

// Resource-oracle calibration (PD1). checkDisk's allocation is linear in the
// number of filesystems scored: measured 13x–26x per-input-byte amplification
// across 24 B–192 KiB (1–8192 filesystems). This fuzz target scores at most a
// handful of filesystems per input, so its allocation is a small constant and the
// 1 MiB AllocFloor is the active bound; factor 128 covers the 26x peak with
// headroom should the input ever scale. Spawns no goroutines (measured Δ=0), no
// disk I/O (pure in-memory verdict) — disk/fd oracle N/A.
const dv1DiskAllocFactor = 128

// FuzzDiskUsageVerdictMonotonic — verdict-integrity fuzzing of the filesystem
// usage / read-only-remount verdict in checkDisk (the live caller dispatched
// from heuristics.go's applyOne). DV1 task names "filesystem nearly full" as a
// monotonicity example and "a writable fs silently remounted read-only" is a
// documented missed-condition class in checkDisk itself.
//
// INVARIANT (disk usage verdict):
//  1. MONOTONICITY. For a writable on-disk filesystem, a HIGHER used-percent
//     never yields a BETTER (lower-severity) verdict than a lower used-percent
//     on an otherwise identical filesystem. Crossing the CRIT threshold scores
//     CRIT; crossing WARN scores at least WARN.
//  2. READ-ONLY REMOUNT IS NOT OK. A writable on-disk filesystem mounted
//     read-only (not an immutable-infra mount, not a ro bind of a device
//     mounted rw elsewhere) must raise at least WARN — the kernel I/O-error
//     remount that checkDisk was specifically added to stop silently passing.
//  3. PERMUTATION INVARIANCE. Reordering independent filesystems does not
//     change the multiset of verdict levels.
//  4. DETERMINISM. The same DiskInfo yields an identical verdict.
//
// All assertions are sound floors (worse input => not-better verdict), never
// ceilings.
//
// What this does NOT verify (honest limits):
//   - It feeds FilesystemInfo directly (post-collector). It proves the scoring
//     monotone; it does not prove the collector computed UsedPct correctly from
//     statfs, nor that it set ReadOnly from /proc/mounts faithfully.
//   - DeviceSizeGB is pinned to 0 so checkDiskGrowth is out of scope here (it
//     has its own fixtures); this target isolates usage + ro-remount.
//   - It uses the default 80/90 thresholds, not the per-cloud-environment
//     adjusted ones.
func FuzzDiskUsageVerdictMonotonic(f *testing.F) {
	f.Add(10.0, 95.0, "ext4", uint8(0), false)
	f.Add(85.0, 50.0, "xfs", uint8(1), false)
	f.Add(99.0, 0.0, "btrfs", uint8(2), true)
	f.Add(0.0, 0.0, "ext4", uint8(0), true)

	thresh := Thresholds{DiskWarnPct: DefaultDiskWarnPct, DiskCritPct: DefaultDiskCritPct}
	writable := []string{"ext4", "xfs", "btrfs", "ext3", "f2fs"}

	// finitePct normalises a fuzzed float into [0,100] and rejects NaN/Inf so the
	// monotone comparison is well defined (NaN/Inf percentages are a parser bug,
	// not a verdict-monotonicity question — out of scope for this oracle).
	finitePct := func(v float64) (float64, bool) {
		if math.IsNaN(v) || math.IsInf(v, 0) {
			return 0, false
		}
		if v < 0 {
			v = 0
		}
		if v > 100 {
			v = 100
		}
		return v, true
	}

	f.Fuzz(func(t *testing.T, lowPct, highPct float64, _fsSeed string, fsSel uint8, readOnly bool) {
		lo, okLo := finitePct(lowPct)
		hi, okHi := finitePct(highPct)
		if !okLo || !okHi {
			return
		}
		if hi < lo {
			lo, hi = hi, lo
		}
		fsType := writable[int(fsSel)%len(writable)]
		if !isWritableOnDiskFS(fsType) {
			t.Fatalf("fixture bug: %q should be a writable on-disk fs", fsType)
		}

		mk := func(usedPct float64, ro bool, dev, mount string) models.DiskInfo {
			return models.DiskInfo{Filesystems: []models.FilesystemInfo{{
				Mount: mount, Device: dev, FSType: fsType,
				TotalGB: 100, UsedPct: usedPct, ReadOnly: ro, DeviceSizeGB: 0,
			}}}
		}

		// Resource oracle: bound the live checkDisk call's allocation/time and
		// record goroutine growth. inputLen is the fuzzed scalars plus the (ignored)
		// fsType seed; the existing monotonicity/false-OK assertions are unchanged.
		n := len(_fsSeed) + 18
		// Oracle 1: monotonicity in used-percent (read-write, so ro logic is off).
		loOut := checkDisk(mk(lo, false, "/dev/sda1", "/data-lo"), thresh)
		var hiOut []models.Insight
		rr := resource.Check(t, n, dv1DiskAllocFactor, func() {
			hiOut = checkDisk(mk(hi, false, "/dev/sdb1", "/data-hi"), thresh)
		})
		if rr.GoroutineDiff > dv1MaxGoroutineDiff {
			t.Fatalf("goroutine growth: checkDisk left %d extra goroutines (input=%d B)", rr.GoroutineDiff, n)
		}
		if levelRankDV1(worstLevelDV1(hiOut)) < levelRankDV1(worstLevelDV1(loOut)) {
			t.Fatalf("MONOTONICITY: usedPct %.2f scored %q but higher %.2f scored a BETTER %q (fs=%s)",
				lo, worstLevelDV1(loOut), hi, worstLevelDV1(hiOut), fsType)
		}
		// Threshold floors (sound, from levelPct's documented bounds).
		if hi >= thresh.DiskCritPct && worstLevelDV1(hiOut) != "CRIT" {
			t.Fatalf("FALSE-OK: usedPct %.2f >= crit %.1f scored %q, want CRIT", hi, thresh.DiskCritPct, worstLevelDV1(hiOut))
		}
		if hi >= thresh.DiskWarnPct && levelRankDV1(worstLevelDV1(hiOut)) < levelRankDV1("WARN") {
			t.Fatalf("FALSE-OK: usedPct %.2f >= warn %.1f scored %q, want >=WARN", hi, thresh.DiskWarnPct, worstLevelDV1(hiOut))
		}

		// Oracle 2: a writable fs mounted read-only is an error remount — not OK.
		// Single filesystem, so its device is not mounted rw elsewhere and it is
		// not an immutable-infra mount (ImmutableRootFS defaults false).
		if readOnly {
			roOut := checkDisk(mk(10, true, "/dev/sdc1", "/var"), thresh)
			if levelRankDV1(worstLevelDV1(roOut)) < levelRankDV1("WARN") {
				t.Fatalf("FALSE-OK: writable %s mounted read-only scored %q, want >=WARN (silent error-remount); insights=%+v",
					fsType, worstLevelDV1(roOut), roOut)
			}
		}

		// Oracle 3: permutation invariance over two independent filesystems.
		fsA := models.FilesystemInfo{Mount: "/a", Device: "/dev/sda1", FSType: fsType, TotalGB: 100, UsedPct: lo}
		fsB := models.FilesystemInfo{Mount: "/b", Device: "/dev/sdb1", FSType: fsType, TotalGB: 100, UsedPct: hi}
		ab := checkDisk(models.DiskInfo{Filesystems: []models.FilesystemInfo{fsA, fsB}}, thresh)
		ba := checkDisk(models.DiskInfo{Filesystems: []models.FilesystemInfo{fsB, fsA}}, thresh)
		if !sameLevelMultiset(ab, ba) {
			t.Fatalf("PERMUTATION: filesystem order changed the verdict multiset:\n ab=%s\n ba=%s", levelsOf(ab), levelsOf(ba))
		}

		// Oracle 4: determinism.
		d := mk(hi, readOnly, "/dev/sdd1", "/srv")
		if !reflect.DeepEqual(checkDisk(d, thresh), checkDisk(d, thresh)) {
			t.Fatalf("NON-DETERMINISM: checkDisk gave two different verdicts for the same input")
		}
	})
}
