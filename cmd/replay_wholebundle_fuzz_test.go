//go:build linux

package cmd

// FuzzWholeBundleReplay drives a fuzzer-crafted capture bundle through the FULL replay
// pipeline (replayBundle → runHealthOnce → every collector via a source.Replay → analysis →
// verdict), the exact path `dsd replay <bundle>` takes. Unlike the per-collector replay
// fuzzers (e.g. FuzzCollectDNFReplay), this covers the INLINE ingest seams that have no
// standalone parser function AND the cross-collector aggregation + verdict that no
// per-parser harness reaches. Replay returns ErrNotRecorded for any input not put in the
// bundle (collectors handle that as "data unavailable"), so a bundle carrying a manifest +
// a few fuzz-controlled seams still exercises the whole collector set end-to-end.
//
// Sound oracles (near-zero false positives):
//   - NO PANIC: the whole pipeline over arbitrary hostile recorded output must not panic.
//     Every field of the manifest and every recorded byte is attacker-controlled in a
//     replayed bundle. A recover() turns a panic into a clean, reproducible failure.
//   - BOUNDED WORK: a crafted bundle must not drive the pipeline into a super-linear
//     blow-up. We assert a generous absolute wall-clock ceiling (a returning run that took
//     this long is an unambiguous accumulation/CPU bomb, not instrumentation jitter — the
//     ceiling is deliberately loose to avoid rig-load flakiness).
// Positive control: replayBundle emits one Result per collector, so a live pipeline always
// returns a non-empty result set — asserted once up front so the no-panic oracle can never
// pass vacuously against a pipeline that silently produced nothing.
//
// Oracle 3 (metamorphic "no verdict flip") shipped separately as
// FuzzWholeBundleReplayVerdictFlip (replay_wholebundle_verdictflip_fuzz_test.go) — its own
// six-seam baseline bundle and provably verdict-neutral mutation set per seam, mirroring
// this file's oracles 1+2 (broad, sound) with a correctness invariant instead.

import (
	"testing"
	"time"

	"github.com/keyorixhq/dashdiag/internal/source"
)

// wholeBundleWorkCeiling is a HANG/blow-up backstop, not a tight performance bound. A benign
// replay is milliseconds; a returning run that took this long over an in-memory bundle is a
// genuine super-linear blow-up. Loose on purpose so instrumentation + rig load never flake it.
const wholeBundleWorkCeiling = 30 * time.Second

// buildWholeBundle assembles a replay bundle: a linux manifest plus fuzz-controlled recorded
// output for a handful of high-value seams. Unrecorded inputs replay as ErrNotRecorded.
func buildWholeBundle(dnfAdvisory, meminfo, loadavg string) *source.Bundle {
	b := source.NewBundle()
	b.Manifest = source.Manifest{
		Format: "dsd-capture-v1", Host: "fuzzhost", OS: "linux",
		GOOS: "linux", DistroID: "fedora", InitSystem: "systemd",
	}
	// Package/advisory inline parse (DNF3/4/5) — gate + fuzzed advisory scan, matching the
	// exact name+args the packages/cve collectors query (see FuzzCollectDNFReplay).
	b.PutCmd("dnf", []string{"repolist", "--enabled", "-q"}, "baseos\nappstream\n", 0)
	b.PutCmd("dnf", []string{"advisory", "list", "--security", "--quiet"}, dnfAdvisory, 0)
	// A couple of file seams parsed inline by the memory / load collectors.
	b.PutFile("/proc/meminfo", []byte(meminfo))
	b.PutFile("/proc/loadavg", []byte(loadavg))
	return b
}

func FuzzWholeBundleReplay(f *testing.F) {
	// Positive control: a benign baseline bundle must yield a non-empty result set.
	base := buildWholeBundle(
		"RHSA-2024:0001 Critical/Sec. openssl-1.1.1w.x86_64\n",
		"MemTotal:       16384000 kB\nMemFree:         8192000 kB\nMemAvailable:   10240000 kB\n",
		"0.10 0.20 0.30 1/234 5678\n",
	)
	if results, _, _ := replayBundle(base, false, true, false, false); len(results) == 0 {
		f.Fatalf("positive control: baseline bundle produced no collector results — pipeline is vacuous")
	}

	f.Add("RHSA-2024:0001 Critical/Sec. openssl-1.1.1w.x86_64\n", "MemTotal: 16384000 kB\n", "0.1 0.2 0.3 1/2 3\n")
	f.Add("FEDORA-2024-abc123 security Important kernel-6.8.0 2024-01-01\n", "", "")
	f.Add("", "", "")
	f.Add("\x00\x00 \t garbage \n\n\n", "MemTotal: notanumber\n", "x y z\n")
	f.Add("ADV only two\nA B\n", "MemFree:\t\t\tkB\n", "9e99 9e99 9e99\n")

	f.Fuzz(func(t *testing.T, dnfAdvisory, meminfo, loadavg string) {
		b := buildWholeBundle(dnfAdvisory, meminfo, loadavg)

		start := time.Now()
		func() {
			defer func() {
				if r := recover(); r != nil {
					t.Fatalf("PANIC in whole-bundle replay pipeline: %v\n dnfAdvisory=%q meminfo=%q loadavg=%q", r, dnfAdvisory, meminfo, loadavg)
				}
			}()
			_, _, _ = replayBundle(b, false, true, false, false)
		}()
		if elapsed := time.Since(start); elapsed > wholeBundleWorkCeiling {
			t.Fatalf("BOUNDED WORK: whole-bundle replay took %s (> %s) — possible accumulation/CPU blow-up", elapsed, wholeBundleWorkCeiling)
		}
	})
}
