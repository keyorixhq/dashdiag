//go:build linux

package collectors

import (
	"context"
	"testing"

	"github.com/keyorixhq/dashdiag/internal/source"
)

// FuzzCollectDNFReplay drives collectDNF through a Replay source built from
// fuzz-controlled `dnf` stdout — the exact path `dsd replay <bundle>` takes when
// a crafted bundle's recorded dnf output is served to the packages collector.
// collectDNF's DNF3/DNF4/DNF5 advisory parse is INLINE (no extracted function),
// so this replay harness is the only way to fuzz it. It records:
//   - the repo gate (dnf --cacheonly repolist --enabled -q) with a non-empty
//     result so dnfHasUpdateRepo passes and the parse loop actually runs —
//     otherwise the collector early-returns and the harness would be silently
//     vacuous;
//   - the advisory scan (dnf --cacheonly advisory list --security --quiet) =
//     the fuzz input.
//
// Command args reference the same package constants the production code uses, so
// the Replay name+args lookup matches by construction. Property: the inline
// advisory parse never panics on hostile dnf output (no trust decision here).
func FuzzCollectDNFReplay(f *testing.F) {
	f.Add("RHSA-2024:0001 Critical/Sec. openssl-1.1.1w.x86_64\n")            // DNF4 shape
	f.Add("FEDORA-2024-abc123 security Important kernel-6.8.0 2024-01-01\n") // DNF5 shape
	f.Add("")
	f.Add("Last metadata expiration check: 0:01:02 ago\nUpdating Subscription Management repositories.\n")
	f.Add("ADV only two\nA B\n")
	f.Add("\x00\x00 \t garbage \n\n\n")
	f.Fuzz(func(t *testing.T, dnfOut string) {
		b := source.NewBundle()
		// Gate: make dnfHasUpdateRepo return true so the parse loop is reached.
		b.PutCmd("dnf", []string{"--cacheonly", "repolist", "--enabled", pkgFlagQ}, "baseos\nappstream\n", 0)
		// The fuzzed advisory scan (collectDNF's primary DNF5 query).
		b.PutCmd("dnf", []string{"--cacheonly", "advisory", "list", flagSecurity, flagQuiet}, dnfOut, 0)

		prev := SetSource(source.NewReplay(b))
		t.Cleanup(func() { SetSource(prev) })

		_, _ = collectDNF(context.Background()) // must not panic
	})
}
