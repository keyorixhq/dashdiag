//go:build linux

package collectors

import (
	"context"
	"strings"
	"testing"

	"github.com/keyorixhq/dashdiag/internal/source"
)

// FuzzCollectDNFVerdict is the verdict-integrity complement to
// FuzzCollectDNFReplay. That harness proves collectDNF's inline DNF advisory
// parse never panics on hostile `dnf` output; this one proves it never silently
// MISPARSES — i.e. the SecurityUpdates count it feeds the security-patch verdict
// exactly equals what collectDNF's own documented rule yields for the same bytes.
// A crafted `dsd replay` bundle drives this counter directly (packages_linux.go:
// info.SecurityUpdates++), so a drift between the parser and its contract is a
// verdict-integrity bug — dashdiag reporting the wrong number of pending security
// updates — not merely a crash.
//
// The oracle re-derives the count independently from the same rule collectDNF
// applies to the advisory scan output: a line contributes iff, after trimming, it
// is non-empty, is not one of the three header prefixes collectDNF skips, and has
// at least three whitespace-separated fields. Kept deliberately in lockstep with
// packages_linux.go's loop: if that loop's skip set or field threshold changes,
// this harness must be updated in the same change — which is the point (it goes
// red on an unreviewed change to how the verdict is counted). Same replay wiring
// as FuzzCollectDNFReplay so the parse loop is actually reached (repo gate primed,
// advisory scan = the fuzz input).
func FuzzCollectDNFVerdict(f *testing.F) {
	f.Add("RHSA-2024:0001 Critical/Sec. openssl-1.1.1w.x86_64\n")                              // DNF4 -> 1
	f.Add("FEDORA-2024-abc123 security Important kernel-6.8.0 2024-01-01\n")                   // DNF5 -> 1
	f.Add("RHSA-1 Critical/Sec. a\nRHSA-2 Moderate/Sec. b\nRHSA-3 Low/Sec. c\n")               // -> 3
	f.Add("Last metadata expiration check: 0:01 ago\nUpdating repos.\nRepositories loaded.\n") // all skipped -> 0
	f.Add("only two\nA B\n\n")                                                                 // <3 fields / blank -> 0
	f.Add("")                                                                                  // -> 0
	f.Add("\x00\x00 \t garbage \n a b c d e \n")                                               // 1 line has >=3 fields -> 1

	f.Fuzz(func(t *testing.T, dnfOut string) {
		b := source.NewBundle()
		// Gate: dnfHasUpdateRepo must return true so collectDNF reaches the parse
		// loop (>=1 non-empty repolist line), else it early-returns and the oracle
		// comparison would be vacuous — the audit's "silently vacuous" trap.
		b.PutCmd("dnf", []string{"repolist", "--enabled", pkgFlagQ}, "baseos\nappstream\n", 0)
		b.PutCmd("dnf", []string{"advisory", "list", flagSecurity, flagQuiet}, dnfOut, 0)

		prev := SetSource(source.NewReplay(b))
		t.Cleanup(func() { SetSource(prev) })

		info, err := collectDNF(context.Background())
		if err != nil {
			t.Fatalf("collectDNF returned an error on a recorded exit-0 advisory scan: %v", err)
		}
		if info == nil {
			t.Fatalf("collectDNF returned nil info with a nil error")
		}

		// Independent oracle over the same bytes and the same rule.
		want := 0
		for _, line := range strings.Split(dnfOut, "\n") {
			line = strings.TrimSpace(line)
			if line == "" ||
				strings.HasPrefix(line, "Last metadata") ||
				strings.HasPrefix(line, "Updating") ||
				strings.HasPrefix(line, "Repositories") {
				continue
			}
			if len(strings.Fields(line)) < 3 {
				continue
			}
			want++
		}

		if info.SecurityUpdates != want {
			t.Fatalf("SecurityUpdates VERDICT MISPARSE: collectDNF counted %d, oracle %d, for advisory output %q", info.SecurityUpdates, want, dnfOut)
		}
		// Structural consistency: one Updates entry per counted advisory, and the
		// severity sub-counts are a subset of the total (never exceed it).
		if len(info.Updates) != info.SecurityUpdates {
			t.Fatalf("Updates slice length %d != SecurityUpdates %d for %q", len(info.Updates), info.SecurityUpdates, dnfOut)
		}
		if info.CriticalUpdates < 0 || info.ImportantUpdates < 0 || info.CriticalUpdates+info.ImportantUpdates > info.SecurityUpdates {
			t.Fatalf("severity sub-counts out of range: critical=%d important=%d total=%d", info.CriticalUpdates, info.ImportantUpdates, info.SecurityUpdates)
		}
	})
}
