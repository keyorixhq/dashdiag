package baseline

import (
	"fmt"
	"math"
	"strconv"
	"strings"
	"testing"
	"time"
)

// FuzzProcStartDifferential checks parseProcStart, which reads every
// /proc/<pid>/stat on the host for `dsd diff --since-deploy` (newestProcStart
// -> RunSinceDeployDiff) to guess the deploy time from the newest process.
// The comm field is chosen by whoever starts the process (prctl
// PR_SET_NAME), so it is the untrusted part; the fields after it are the
// kernel's. The record is assembled as "<pid> (<comm>) <tail>".
//
// Oracles:
//
//  1. Differential against a proc(5) reference: comm runs from the first "("
//     to the LAST ")", starttime is field 22 as an unsigned decimal integer of
//     clock ticks (USER_HZ 100), start = boot + ticks/100 whole seconds. When
//     the reference accepts and the result is representable as a
//     time.Duration, parseProcStart must accept and return the same name and
//     the same start time.
//  2. Sanity bound: whenever parseProcStart accepts, the start time is not
//     before boot (the kernel counts starttime up from boot).
//  3. Metamorphic comm: swapping comm for any other comm (spaces, parens,
//     fake fields) with the same kernel tail leaves the start time unchanged
//     and returns the new comm as the name.
//  4. parseBootTime round trip: a /proc/stat with "btime N" among other lines
//     yields time.Unix(N, 0).
//
// What it does NOT verify: tails containing ")" (the kernel never writes one
// after comm; such inputs are skipped for oracles 1 and 3), USER_HZ other than
// 100, the age filter and newest-pick in newestProcStartFrom, or how the name
// is later printed (FuzzTaintBaselineNames covers output sanitising).
func FuzzProcStartDifferential(f *testing.F) {
	kernelTail := "S 1 4242 4242 0 -1 4194560 2637 0 0 0 5 3 0 0 20 0 1 0 123456 12345678 900 18446744073709551615 1 1 0 0 0 0 0 0 0 0 0 0 17 2 0 0 0 0 0"
	for _, s := range []struct{ comm, comm2, tail string }{
		{"bash", "Web Content", kernelTail},
		{"a) R 1 2 3", "((x))", kernelTail},
		{"", ") ", kernelTail},
		{"kworker/0:1H", "x", strings.Replace(kernelTail, "123456", "99", 1)},
		{"nan", "inf", strings.Replace(kernelTail, "123456", "NaN", 1)},
		{"e", "f", strings.Replace(kernelTail, "123456", "1e5", 1)},
		{"short", "s", "S 1 2"},
	} {
		f.Add(s.comm, s.comm2, s.tail, int64(1_700_000_000))
	}
	f.Fuzz(func(t *testing.T, comm, comm2, tail string, btime int64) {
		if len(comm)+len(comm2)+len(tail) > 4096 {
			return
		}
		boot := time.Unix(1_700_000_000, 0)
		rec := "4242 (" + comm + ") " + tail
		got, name, ok := parseProcStart(strings.NewReader(rec), boot)

		// Oracle 2.
		if ok && got.Before(boot) {
			t.Fatalf("start time %v is before boot %v for %q", got, boot, rec)
		}

		if !strings.Contains(tail, ")") {
			// Oracle 1.
			fields := strings.Fields(tail)
			if len(fields) >= 20 {
				if ticks, err := strconv.ParseUint(fields[19], 10, 64); err == nil && ticks/100 <= math.MaxInt64/uint64(time.Second) {
					want := boot.Add(time.Duration(ticks/100) * time.Second) //nolint:gosec // bounded above
					if !ok {
						t.Fatalf("reference accepts starttime %d but parseProcStart rejects %q", ticks, rec)
					}
					if name != comm || !got.Equal(want) {
						t.Fatalf("parseProcStart(%q) = (%v, %q), reference (%v, %q)", rec, got, name, want, comm)
					}
				}
			}
			// Oracle 3.
			got2, name2, ok2 := parseProcStart(strings.NewReader("4242 ("+comm2+") "+tail), boot)
			if ok2 != ok || (ok && (!got2.Equal(got) || name2 != comm2)) {
				t.Fatalf("comm %q -> %q changes the result: (%v,%q,%v) -> (%v,%q,%v), tail %q",
					comm, comm2, got, name, ok, got2, name2, ok2, tail)
			}
		}

		// Oracle 4.
		stat := fmt.Sprintf("cpu  1 2 3 4\nintr 5\nbtime %d\nprocesses 9\n", btime)
		bt, bok := parseBootTime(strings.NewReader(stat))
		if !bok || !bt.Equal(time.Unix(btime, 0)) {
			t.Fatalf("parseBootTime(%q) = (%v, %v), want %v", stat, bt, bok, time.Unix(btime, 0))
		}
	})
}
