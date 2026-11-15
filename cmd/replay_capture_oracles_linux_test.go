//go:build linux

package cmd

// Committed, deterministic DD2 oracles over the two replay-fidelity fixtures
// (no external captures needed, so these run in CI). They are the fast,
// red-provable regression guards that back the heavier env-gated sweep
// (TestDD2CaptureReplaySweep) and the continuous fuzz target
// (FuzzCaptureReplayMutationRobustness):
//
//   - Oracle 1 (determinism / no panic): three replays of the same bundle must
//     produce the identical per-check verdict map, and none may panic. A verdict
//     that drifts across replays of a fixed input means a collector read live
//     state (clock, container-context, time) instead of the bundle.
//   - Oracle 2 (anti-false-OK): applying each information-destroying damage kind
//     to each recorded blob must never turn a baseline non-OK check into "OK".
//
// WHAT THESE DO NOT VERIFY: the fixtures are two snapshots of ONE host (root and
// non-root captures of a VMware Debian 13 guest). They prove replay is a pure
// function of the bundle and fails closed under damage — not that the baseline
// verdicts are themselves correct, nor that other hosts behave the same.

import (
	"testing"
	"time"

	"github.com/keyorixhq/dashdiag/internal/source"
)

// dd2CommittedFixtures are the committed replay-fidelity bundles.
func dd2CommittedFixtures(t *testing.T) []string {
	t.Helper()
	root := dd2RepoRoot()
	return []string{
		root + "/fixtures/replay-fidelity/debian13-vmware-unsynced.tar.gz",
		root + "/fixtures/replay-fidelity/debian13-vmware-nonroot.tar.gz",
	}
}

// replayDirVerdicts loads an on-disk raw-v1 bundle dir and returns its verdict map.
func replayDirVerdicts(t *testing.T, dir string) map[string]string {
	t.Helper()
	b, err := source.Load(dir)
	if err != nil {
		t.Fatalf("load bundle dir: %v", err)
	}
	results, insights, _ := replayBundle(b, false, true, false, false)
	return verdictMap(results, insights)
}

func TestDD2FixtureReplayDeterminismAndNoPanic(t *testing.T) {
	dd2CapParallelism()
	for _, fx := range dd2CommittedFixtures(t) {
		fx := fx
		t.Run(baseName(fx), func(t *testing.T) {
			var first map[string]string
			for i := 0; i < 3; i++ {
				var got map[string]string
				func() {
					defer func() {
						if r := recover(); r != nil {
							t.Fatalf("PANIC replaying %s (iteration %d): %v", fx, i, r)
						}
					}()
					b, err := loadBundle(fx)
					if err != nil {
						t.Fatalf("load %s: %v", fx, err)
					}
					results, insights, _ := replayBundle(b, false, true, false, false)
					got = verdictMap(results, insights)
				}()
				if i == 0 {
					first = got
					continue
				}
				if !sameVerdicts(first, got) {
					t.Fatalf("NON-DETERMINISTIC replay of %s: iteration %d verdict map differs from the first", fx, i)
				}
			}
			if len(first) == 0 {
				t.Fatalf("%s produced no checks — pipeline vacuous", fx)
			}
		})
	}
}

func TestDD2FixtureMutationAntiFalseOK(t *testing.T) {
	dd2CapParallelism()
	const kinds = 8 // damageBlob kinds 0..6 + drop (7)
	for _, fx := range dd2CommittedFixtures(t) {
		fx := fx
		t.Run(baseName(fx), func(t *testing.T) {
			b0, err := loadBundle(fx)
			if err != nil {
				t.Fatalf("load %s: %v", fx, err)
			}
			baseDir := t.TempDir()
			if err := b0.Save(baseDir); err != nil {
				t.Fatalf("save %s: %v", fx, err)
			}
			baseTree, err := readTree(baseDir)
			if err != nil {
				t.Fatalf("read tree: %v", err)
			}
			blobs := blobList(baseTree)
			if len(blobs) == 0 {
				t.Fatalf("%s has no blobs to damage", fx)
			}
			baselineNonOK := dd2BaselineNonOK(t, baseDir)
			if len(baselineNonOK) == 0 {
				t.Fatalf("%s has no non-OK baseline check — anti-false-OK oracle vacuous", fx)
			}

			// A bounded, deterministic set of (blob, kind) cases: every damage kind
			// on every blob would be minutes of full-pipeline replays (too slow for
			// CI) — the fuzz target and the env-gated 49-capture sweep provide the
			// exhaustive/continuous coverage. Here each blob gets one rotating kind,
			// and every kind is additionally forced on the first few blobs, so all
			// kinds are exercised and a broad spread of blobs is damaged.
			const maxCases = 16 // keep this committed guard CI-fast (each case rewrites
			// and reloads the whole bundle tree); the fuzz target
			// and the env-gated 49-capture sweep provide exhaustive/continuous coverage.
			type dcase struct{ bi, kind int }
			seen := map[dcase]bool{}
			var cases []dcase
			add := func(bi, kind int) {
				if len(cases) >= maxCases {
					return
				}
				c := dcase{bi % len(blobs), kind % kinds}
				if !seen[c] {
					seen[c] = true
					cases = append(cases, c)
				}
			}
			// Every kind at least once, then a spread of blobs at a stride so the
			// sample covers early/middle/late blobs without running hundreds.
			for kind := 0; kind < kinds; kind++ {
				add(kind%len(blobs), kind)
			}
			stride := len(blobs)/maxCases + 1
			for bi := 0; bi < len(blobs); bi += stride {
				add(bi, bi)
			}
			for _, c := range cases {
				bi, kind := c.bi, c.kind
				{
					dir := t.TempDir()
					dd2ApplyDamage(dir, baseTree, blobs, bi, kind, "")
					var damaged map[string]string
					start := time.Now()
					func() {
						defer func() {
							if r := recover(); r != nil {
								t.Fatalf("PANIC: blob=%s kind=%d: %v", blobs[bi], kind, r)
							}
						}()
						b, err := source.Load(dir)
						if err != nil {
							return // fail-closed load error is fine
						}
						results, insights, _ := replayBundle(b, false, true, false, false)
						damaged = verdictMap(results, insights)
					}()
					if el := time.Since(start); el > mutationWorkCeiling {
						t.Fatalf("BOUNDED WORK: blob=%s kind=%d took %s", blobs[bi], kind, el)
					}
					if damaged == nil {
						continue
					}
					for name, baseStatus := range baselineNonOK {
						if got, ok := damaged[name]; ok && got == "OK" {
							t.Fatalf("FALSE-OK: %s check %q was %s on the undamaged baseline but replayed OK after damaging blob=%s kind=%d — lost information must surface as unknown, not healthy",
								baseName(fx), name, baseStatus, blobs[bi], kind)
						}
					}
				}
			}
		})
	}
}
