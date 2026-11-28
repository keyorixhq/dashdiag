//go:build linux

package cmd

// FuzzWholeBundleReplayCountDelta is oracle 4 for the whole-bundle replay fuzzer —
// the POSITIVE half that FuzzWholeBundleReplayVerdictFlip (oracle 3) deliberately
// left open. Where oracle 3 asserts that a provably verdict-NEUTRAL mutation never
// changes the verdict class, this one asserts the opposite-direction metamorphic
// property: adding EXACTLY ONE well-formed, countable record to a seam increases
// that seam's reported count by EXACTLY ONE (and never lets the overall verdict
// class decrease). Same idiom, same fixed baseline bundle
// (buildBundleFrom(seamDefaults()) from the verdictflip file), same
// no-second-implementation / no-hand-written-expected-output discipline: the only
// "expected" value is baseline+1, read from the SAME observable on the unmutated run.
//
// The added record is decoded from fuzz bytes within a grammar that is VALID BY
// CONSTRUCTION. In every seam the fuzz-controlled bytes fill a NON-counted free slot
// (the advisory id / package name, the SMART attribute-ID column, the EDAC
// controller directory-name suffix) via sanitizeCountToken, which strips everything
// but [A-Za-z0-9._-] so the slot is always a single whitespace-free token that
// cannot split the record's fields or match a skip-prefix. The counted quantity
// itself is fixed, so the delta is provably +1 for any correct parser:
//
//   - dnf   : one DNF4 advisory line "<id> <sev>/Sec. <pkg>". packages_linux.go:364
//             Fields() yields exactly 3 fields; :365 (len<3 skip) does not fire; :373
//             takes the DNF4 branch because fields[1] contains "/"; :397
//             SecurityUpdates++ runs UNCONDITIONALLY for every non-skipped advisory,
//             so SecurityUpdates rises by exactly 1 regardless of which severity the
//             fuzz byte selects. Observable: PackagesInfo.SecurityUpdates.
//   - edac-ce: one extra controller directory "mcf<suffix>" with ce_count=1, ue_count=0.
//             edac_linux.go:37 HasPrefix "mc" accepts it (the literal "mcf" prefix can
//             never equal mc0/mc1, so it is a NEW, distinct controller); :43 fileExists
//             ce_count passes (seeded); :47-48 readEDACCounter returns ce=1,ue=0; :53
//             corrected += 1. Observable: MemoryInfo.CorrectedErrors.
//   - edac-ue: (DD-VERDICT-2 Part B) one extra controller "mcu<suffix>" with ce_count=0,
//             ue_count=1. Same gates as edac-ce; :54 uncorrected += 1. Observable:
//             MemoryInfo.UncorrectedErrors.
//   - smart : one SATA failure-attribute line whose NAME contains
//             "offline_uncorrectable" and whose RAW_VALUE (last of >=10 fields) is 1.
//             disk_linux.go:343 isSATAFailureAttr matches; :263 len>=10 holds (the
//             fixed "F"-prefixed id keeps the first column non-empty); :264-265
//             MediaErrors += 1. Observable: sum of DiskInfo.Drives[].SMART.MediaErrors.
//
// Positive control (run once, before f.Fuzz): every seam must yield a non-zero
// countable baseline — otherwise "+1" could pass vacuously against a seam that
// produced nothing. A per-iteration vacuity guard re-checks after each mutation.
//
// Does NOT verify: that the chosen severity's PER-SEVERITY bucket (CriticalUpdates /
// ImportantUpdates) moves by one — only the aggregate SecurityUpdates is asserted, so
// a bug that miscredited severity buckets while keeping the total correct would pass
// here (oracle 3's dnf mutations, and the dedicated per-collector DNF fuzzers, cover
// severity classification). Does NOT verify any seam not listed above, NVMe media
// errors (the colon/value branch, not the SATA sum), insight TEXT or rendered prose
// (only the collector-result count), or that the verdict class is EXACTLY right —
// only that adding a record never makes it artificially healthier (no decrease). Does
// NOT verify "+N" for N>1; each mutation adds exactly one record by construction.

import (
	"strings"
	"testing"
	"time"

	"github.com/keyorixhq/dashdiag/internal/fuzzutil"
	"github.com/keyorixhq/dashdiag/internal/models"
	"github.com/keyorixhq/dashdiag/internal/runner"
	"github.com/keyorixhq/dashdiag/internal/source"
)

// sanitizeCountToken keeps only [A-Za-z0-9._-] from fuzz bytes. The result is always
// a single whitespace-free token (possibly empty), safe to drop into a record's
// non-counted free slot without splitting its fields or introducing a newline that
// would smuggle in a second record. Mirrors the verdictflip file's oneLine/noColon
// guarantees, tightened to "field-safe token" because here the slot is a single field.
func sanitizeCountToken(s string) string {
	var b strings.Builder
	for _, r := range s {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9',
			r == '.', r == '-', r == '_':
			b.WriteRune(r)
		}
	}
	return b.String()
}

// dnfCountSeverities are the four severity tokens the fuzz byte selects between. All
// four are counted the same way by SecurityUpdates++ (packages_linux.go:397); varying
// them exercises the severity-classification switch (:387-395) without changing the
// asserted +1 on the aggregate count.
var dnfCountSeverities = []string{"Critical", "Important", "Moderate", "Low"}

// ── +1 record builders (baseline bundle + exactly one added record) ───────────────

func dnfAddOneRecord(extra string) *source.Bundle {
	tok := sanitizeCountToken(extra)
	sev := dnfCountSeverities[len(extra)%len(dnfCountSeverities)]
	// id starts with the literal "FUZZ-" so the line can never match collectDNF's
	// "Last metadata"/"Updating"/"Repositories" skip-prefixes and is never empty.
	line := "FUZZ-" + tok + " " + sev + "/Sec. pkg-" + tok
	c := seamDefaults()
	c.dnfLine2 = c.dnfLine2 + "\n" + line // one extra advisory line in the -A output
	return buildBundleFrom(c)
}

func edacAddOneRecord(extra string) *source.Bundle {
	b := buildBundleFrom(seamDefaults())
	// "mcf"+suffix: HasPrefix "mc" is true, yet the 'f' after "mc" guarantees it is
	// never mc0/mc1, so it is a genuinely new, distinct controller contributing ce=1.
	name := "mcf" + sanitizeCountToken(extra)
	b.PutDir("/sys/devices/system/edac/mc", []string{"mc0", "mc1", name})
	p := "/sys/devices/system/edac/mc/" + name
	b.PutStat(p+"/ce_count", source.FileMeta{})
	b.PutFile(p+"/ce_count", []byte("1\n"))
	b.PutFile(p+"/ue_count", []byte("0\n"))
	return b
}

// edacUEAddOneRecord adds one controller with ue_count=1 (ce_count=0), the
// UncorrectedErrors sibling of edacAddOneRecord (DD-VERDICT-2 Part B). ce_count=0 is
// a VALID, readable counter (edac_linux.go:47-48 readEDACCounter parses "0" fine, so
// the controller is NOT skipped as unreadable at :49-51), contributing 0 to the
// corrected sum and exactly 1 to the uncorrected sum (edac_linux.go:54
// uncorrected += ue). Observable: MemoryInfo.UncorrectedErrors.
func edacUEAddOneRecord(extra string) *source.Bundle {
	b := buildBundleFrom(seamDefaults())
	name := "mcu" + sanitizeCountToken(extra)
	b.PutDir("/sys/devices/system/edac/mc", []string{"mc0", "mc1", name})
	p := "/sys/devices/system/edac/mc/" + name
	b.PutStat(p+"/ce_count", source.FileMeta{})
	b.PutFile(p+"/ce_count", []byte("0\n"))
	b.PutFile(p+"/ue_count", []byte("1\n"))
	return b
}

func smartAddOneRecord(extra string) *source.Bundle {
	// 10 whitespace fields, RAW_VALUE=1 last, NAME carries the SATA failure trigger.
	// The "F"-prefixed id keeps the first column non-empty so len(fields) stays >=10.
	line := "F" + sanitizeCountToken(extra) +
		" Offline_Uncorrectable 0x0032 100 100 000 Pre-fail Always - 1"
	c := seamDefaults()
	c.smartAttrLine2 = c.smartAttrLine2 + "\n" + line
	return buildBundleFrom(c)
}

// ── observables (the most direct countable surface per seam) ──────────────────────

func dnfCount(results []runner.Result) (int64, bool) {
	r := findResult(results, "Packages")
	if r == nil {
		return 0, false
	}
	info, ok := r.Data.(*models.PackagesInfo)
	if !ok || info == nil {
		return 0, false
	}
	return int64(info.SecurityUpdates), info.SecurityUpdates > 0
}

func edacCount(results []runner.Result) (int64, bool) {
	r := findResult(results, "Memory")
	if r == nil {
		return 0, false
	}
	info, ok := r.Data.(*models.MemoryInfo)
	if !ok || info == nil {
		return 0, false
	}
	return info.CorrectedErrors, info.EDACAvailable && info.CorrectedErrors > 0
}

// edacUECount observes UncorrectedErrors. "Produced" is EDACAvailable (the seam ran),
// NOT UncorrectedErrors>0 — the baseline UE is legitimately 0, and the +1 oracle
// asserts adding a ue=1 controller makes it exactly 1. EDACAvailable proves the seam
// is live, so the oracle is not vacuous despite the zero baseline value.
func edacUECount(results []runner.Result) (int64, bool) {
	r := findResult(results, "Memory")
	if r == nil {
		return 0, false
	}
	info, ok := r.Data.(*models.MemoryInfo)
	if !ok || info == nil {
		return 0, false
	}
	return info.UncorrectedErrors, info.EDACAvailable
}

func smartCount(results []runner.Result) (int64, bool) {
	r := findResult(results, "Disk")
	if r == nil {
		return 0, false
	}
	info, ok := r.Data.(*models.DiskInfo)
	if !ok || info == nil {
		return 0, false
	}
	var sum int64
	produced := false
	for _, d := range info.Drives {
		if d.SMART != nil {
			sum += d.SMART.MediaErrors
			if d.SMART.MediaErrors > 0 {
				produced = true
			}
		}
	}
	return sum, produced
}

// ── mutation table ────────────────────────────────────────────────────────────────

type countMutation struct {
	seam    string
	build   func(extra string) *source.Bundle // baseline + exactly one added record
	observe func(results []runner.Result) (int64, bool)
}

func countMutations() []countMutation {
	return []countMutation{
		{seam: "dnf", build: dnfAddOneRecord, observe: dnfCount},
		{seam: "edac-ce", build: edacAddOneRecord, observe: edacCount},
		{seam: "edac-ue", build: edacUEAddOneRecord, observe: edacUECount},
		{seam: "smart", build: smartAddOneRecord, observe: smartCount},
	}
}

// ── the fuzz target ───────────────────────────────────────────────────────────────

func FuzzWholeBundleReplayCountDelta(f *testing.F) {
	muts := countMutations()

	// POSITIVE CONTROL — the unmutated baseline must produce a non-zero countable
	// value for every seam (so "+1" can never pass vacuously) and a non-trivial
	// verdict class (so "no decrease" has somewhere to decrease FROM).
	baseBundle := buildBundleFrom(seamDefaults())
	baseResults, baseInsights, _ := replayBundle(baseBundle, false, true, false, false)
	baseVerdict := verdictClass(baseInsights)
	if baseVerdict == 0 {
		f.Fatalf("positive control: baseline bundle yielded verdict OK (0) — expected a non-trivial WARN verdict with headroom to observe an escalation")
	}
	baseCounts := make([]int64, len(muts))
	for i, m := range muts {
		cnt, ok := m.observe(baseResults)
		if !ok {
			f.Fatalf("positive control: seam %q produced no countable baseline data — the +1 oracle would be vacuous for this seam", m.seam)
		}
		baseCounts[i] = cnt
	}

	for i := range muts {
		f.Add(uint8(i), "")
		f.Add(uint8(i), "x")
	}
	f.Add(uint8(0), "crit\x00\t\n and noise")

	f.Fuzz(func(t *testing.T, selRaw uint8, extra string) {
		idx := int(selRaw) % len(muts)
		m := muts[idx]
		b := m.build(extra)

		var results []runner.Result
		var insights []models.Insight
		start := time.Now()
		func() {
			defer func() {
				if r := recover(); r != nil {
					t.Fatalf("PANIC in whole-bundle replay pipeline (seam=%s extra=%q): %v", m.seam, extra, r)
				}
			}()
			results, insights, _ = replayBundle(b, false, true, false, false)
		}()
		if elapsed, _ := fuzzutil.EffectiveElapsed(start); elapsed > wholeBundleWorkCeiling {
			t.Fatalf("BOUNDED WORK: whole-bundle replay took %s (> %s) under seam=%s", elapsed, wholeBundleWorkCeiling, m.seam)
		}

		cnt, ok := m.observe(results)
		if !ok {
			t.Fatalf("seam %q produced no data after the +1 mutation (extra=%q) — the added record broke collection instead of adding exactly one", m.seam, extra)
		}
		if want := baseCounts[idx] + 1; cnt != want {
			t.Fatalf("+1 COUNT MISMATCH under seam=%s (extra=%q): baseline=%d, adding exactly one record must give %d, got %d",
				m.seam, extra, baseCounts[idx], want, cnt)
		}
		if got := verdictClass(insights); got < baseVerdict {
			t.Fatalf("VERDICT DECREASED under seam=%s (extra=%q): base=%d got=%d — adding a record made the system report as healthier",
				m.seam, extra, baseVerdict, got)
		}
	})
}
