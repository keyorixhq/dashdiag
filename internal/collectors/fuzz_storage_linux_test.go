//go:build linux

package collectors

import (
	"math"
	"testing"
)

// These fuzz the raw-tool parsers whose numeric output feeds a health verdict, in
// the spirit of the smartctl/NVMe fuzzers (#200/#201): garbled or hostile tool
// output must not panic, and must not produce a NEGATIVE count that slips under a
// `> 0` / `sum == 0` verdict (the false-OK class) or a NaN/Inf percentage.

// FuzzParseZFSVdevErrors: error counts feed `ReadErrors+WriteErrors+CksumErrors
// == 0` (heuristics_storage.go) and an "R:%d W:%d C:%d" display. A negative count
// from a garbled vdev line would corrupt both.
func FuzzParseZFSVdevErrors(f *testing.F) {
	f.Add("  sda       ONLINE       0     0     0")
	f.Add("  sdb       DEGRADED     5     0     2")
	f.Add("\tmirror-0  ONLINE       0     0     0\n  sdc ONLINE 1 2 3")
	f.Add("pool: tank\n state: ONLINE\n  raidz1 DEGRADED -5 0 K")
	f.Fuzz(func(t *testing.T, out string) {
		r, w, c := parseZFSVdevErrors(out)
		if r < 0 || w < 0 || c < 0 {
			t.Fatalf("negative ZFS vdev error count from %q: read=%d write=%d cksum=%d", out, r, w, c)
		}
	})
}

// FuzzParseZFSCount: the K/M/G suffix parser behind the vdev counts. A count that
// feeds a `> 0` health check must never be negative.
func FuzzParseZFSCount(f *testing.F) {
	for _, s := range []string{"0", "5", "1K", "2.3M", "10G", "-5", "-1K", "", "K", "abc", "99999999999999999999"} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		if n, ok := parseZFSCount(s); ok && n < 0 {
			t.Fatalf("parseZFSCount(%q) returned negative count %d", s, n)
		}
	})
}

// FuzzParseMDArrayCounts: mdstat "[total/active]". When ok, the counts feed a
// degraded-array verdict (active < total) — negatives would invert it.
func FuzzParseMDArrayCounts(f *testing.F) {
	f.Add("      1234 blocks super 1.2 [2/2] [UU]")
	f.Add("      1234 blocks [4/3] [UUU_]")
	f.Add("[/] [-1/-1] []")
	f.Fuzz(func(t *testing.T, line string) {
		total, active, ok := parseMDArrayCounts(line)
		if ok && (total < 0 || active < 0) {
			t.Fatalf("negative md array count from %q: total=%d active=%d", line, total, active)
		}
	})
}

// FuzzParseRecoveryPct: a rebuild percentage. Must stay a finite, non-negative
// number — a NaN/Inf or negative would corrupt the rebuild-progress display/verdict.
func FuzzParseRecoveryPct(f *testing.F) {
	f.Add("[===>.................]  recovery = 23.4% (1234/5678) finish=1.0min")
	f.Add("resync = 100.0%")
	f.Add("recovery = -inf% (x/y)")
	f.Fuzz(func(t *testing.T, line string) {
		pct := parseRecoveryPct(line)
		if math.IsNaN(pct) || math.IsInf(pct, 0) || pct < 0 {
			t.Fatalf("parseRecoveryPct(%q) = %v (want finite, non-negative)", line, pct)
		}
	})
}

// FuzzParseDRBDSyncLine: sync percentage + KB remaining. Both feed progress
// reporting; neither should be NaN/Inf or negative.
func FuzzParseDRBDSyncLine(f *testing.F) {
	f.Add("  [>....................] sync'ed:  0.3% (524236/524288)K")
	f.Add("  [==========>.........] sync'ed: 53.9% (1234/5678)K")
	f.Add("sync'ed: -1e9% (-5/-5)K")
	f.Fuzz(func(t *testing.T, line string) {
		pct, kb := parseDRBDSyncLine(line)
		if math.IsNaN(pct) || math.IsInf(pct, 0) || pct < 0 {
			t.Fatalf("parseDRBDSyncLine(%q) pct=%v (want finite, non-negative)", line, pct)
		}
		if kb < 0 {
			t.Fatalf("parseDRBDSyncLine(%q) kbLeft=%d (want non-negative)", line, kb)
		}
	})
}
