//go:build linux

package collectors

import (
	"fmt"
	"sort"
	"strings"
	"testing"

	"github.com/keyorixhq/dashdiag/internal/models"
)

// FuzzAptAccumulateUpdateMetamorphic is a METAMORPHIC verdict-integrity fuzzer for the
// apt security-update counter. Where FuzzAptAccumulateUpdate asserts "never panics", this
// asserts a correctness invariant with NO second implementation and NO hand-specified
// expected output: the verdict must be invariant under transforms that cannot legitimately
// change it.
//
// aptAccumulateUpdate is purely additive per line (severity depends only on the line's own
// fields[1] vs the fixed criticalPkgs set; there is no cross-line state), so:
//   - PERMUTATION invariance: processing the same lines in any order yields the same
//     {SecurityUpdates, CriticalUpdates, ImportantUpdates} counts and the same multiset of
//     Updates. A violation means someone introduced order-dependent logic (stateful
//     accumulation, an order-sensitive dedup) — a silent miscount of pending security updates.
//   - NEUTRAL-LINE invariance: interleaving clearly-neutral lines (empty / whitespace /
//     single-field, which the <2-fields guard skips) must not change the verdict. A violation
//     means a "should be ignored" line is being counted.
//
// Both are sound: they assert only equalities that hold for any correct additive counter, so
// there is no false-positive direction. Reporting the wrong number of pending security
// updates is a trust failure, not a crash — this is the dashdiag analogue of a keyorix
// security invariant. Runs on attacker-controlled tool output via `dsd replay`.
func FuzzAptAccumulateUpdateMetamorphic(f *testing.F) {
	f.Add("Inst openssl [1] (2 Ubuntu:22.04/jammy-security [amd64])\n" +
		"Inst curl [1] (2 amd64)\nInst linux-image-generic [1] (2 amd64)")
	f.Add("a b\nc d\ne f\ng h")
	f.Add("Inst libc6 [1] (2 x)\n\nInst sudo [1] (2 y)\n   \nInst bash [1] (2 z)")
	f.Add("")
	f.Add("one\ntwo\nthree")

	crit := map[string]bool{
		"linux-image": true, "openssl": true, "openssh-server": true,
		"libc6": true, "curl": true, "sudo": true, "bash": true,
	}

	verdict := func(lines []string) (sec, critc, imp int, updates string) {
		info := &models.PackagesInfo{Checked: true, PackageManager: "apt"}
		for _, l := range lines {
			aptAccumulateUpdate(info, crit, l)
		}
		ups := make([]string, 0, len(info.Updates))
		for _, u := range info.Updates {
			ups = append(ups, fmt.Sprintf("%s\x00%v", u.Name, u.Severity))
		}
		sort.Strings(ups) // multiset, order-independent
		return info.SecurityUpdates, info.CriticalUpdates, info.ImportantUpdates, strings.Join(ups, "\n")
	}
	same := func(name string, t *testing.T, lines []string, s0, c0, i0 int, u0 string) {
		s, c, i, u := verdict(lines)
		if s != s0 || c != c0 || i != i0 || u != u0 {
			t.Fatalf("VERDICT NOT INVARIANT under %s:\n base=(sec=%d crit=%d imp=%d)\n got =(sec=%d crit=%d imp=%d)\n baseUpdates=%q\n gotUpdates=%q",
				name, s0, c0, i0, s, c, i, u0, u)
		}
	}

	f.Fuzz(func(t *testing.T, raw string) {
		lines := strings.Split(raw, "\n")
		s0, c0, i0, u0 := verdict(lines)

		// PERMUTATION 1: full reverse.
		rev := make([]string, len(lines))
		for k := range lines {
			rev[k] = lines[len(lines)-1-k]
		}
		same("reverse", t, rev, s0, c0, i0, u0)

		// PERMUTATION 2: rotate by one (a different permutation) when it is one.
		if len(lines) > 1 {
			rot := append(append([]string{}, lines[1:]...), lines[0])
			same("rotate-by-1", t, rot, s0, c0, i0, u0)
		}

		// NEUTRAL INSERTION: interleave lines the <2-fields guard must skip.
		withNeutral := make([]string, 0, len(lines)*4+2)
		for _, l := range lines {
			withNeutral = append(withNeutral, "", "   ", "singletoken", l)
		}
		withNeutral = append(withNeutral, "", "\t\t")
		same("neutral-line insertion", t, withNeutral, s0, c0, i0, u0)
	})
}
