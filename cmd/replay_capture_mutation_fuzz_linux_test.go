//go:build linux

package cmd

// FuzzCaptureReplayMutationRobustness is DD2 oracle 2: capture-replay mutation
// robustness. It takes a REAL committed capture bundle (fixtures/replay-fidelity,
// a sanitized `dsd capture --raw` of a distinctive VMware Debian 13 host) and
// applies ONE piece of structured, strictly information-DESTROYING damage to a
// single recorded file or command output — truncate, drop, garble digits,
// uppercase-shift, blank to whitespace, or splice provably-non-data noise — then
// replays the damaged bundle through the full `dsd replay` pipeline (loadBundle →
// replayBundle → render verdicts).
//
// The oracle is three-fold:
//   - NO PANIC: the whole pipeline over a damaged bundle must not panic.
//   - BOUNDED WORK: a damaged bundle must not drive the pipeline past a loose
//     wall-clock ceiling (a hang/blow-up backstop, not a tight perf bound).
//   - ANTI-FALSE-OK (the correctness invariant): a check that the UNDAMAGED
//     baseline reported as non-OK (CRIT / WARN / ERROR) must never flip to a
//     confident "OK" purely because information was removed or garbled. It is
//     allowed to stay non-OK, to change among non-OK classes, or to drop out of
//     checks[] entirely (the collector honestly degrades to not-recorded /
//     not-applicable — "unknown", not "healthy"). It must not say OK. This is the
//     dashdiag analogue of a keyorix "fail closed, not open" invariant: losing
//     your inputs must surface as unknown, never as a green light.
//
// SOUNDNESS. The invariant is one-directional (non-OK must not become OK), so a
// mutation must never INTRODUCE valid data that could legitimately earn an OK.
// Every damage kind here only removes or garbles bytes that already existed; the
// two splice kinds insert noise with every ASCII letter and digit stripped out
// (sanitizeNoise), so the inserted bytes can never form a parseable record
// (no "nameserver 8.8.8.8", no "MemTotal: 16 kB"). Thus any non-OK→OK flip is a
// genuine false-OK (a collector concluding "healthy" from strictly-less
// information), never an artifact of the harness feeding the collector a cure.
//
// POSITIVE CONTROL (run once, before f.Fuzz): the undamaged baseline must report
// at least one non-OK check, or the anti-false-OK oracle would be vacuous. The
// unsynced fixture pins Clock=CRIT, Network=CRIT, Hardening/KernelSec/VMware=WARN.
//
// WHAT THIS DOES NOT VERIFY. A fixture is one host at one instant, not a spec:
//   - It does not prove the baseline verdicts are themselves correct, only that
//     damage cannot bleach a non-OK one to OK.
//   - It damages exactly one input at a time; multi-input corruption is out of
//     scope.
//   - It cannot see a false-OK on a check the baseline already reports OK (there
//     is no non-OK verdict there to protect). The broader sweep over all staged
//     captures (TestDD2CaptureMutationSweep) widens the baseline set but has the
//     same single-direction limit.

import (
	"encoding/json"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/keyorixhq/dashdiag/internal/source"
	"github.com/keyorixhq/dashdiag/internal/testutil/srcpath"
)

// mutationWorkCeiling is the per-input hang/blow-up backstop. Replaying a small
// in-memory bundle is milliseconds; a returning run this slow is a genuine
// accumulation bomb, not jitter. Loose on purpose (fuzz workers are documented to
// hang ~10s/input; this is the outer bound that turns a hang into a clean fail).
const mutationWorkCeiling = 20 * time.Second

// dd2MutationFixture is the committed baseline. The unsynced capture is chosen
// for its rich non-OK verdict set (Clock/Network CRIT; Hardening/KernelSec/VMware
// WARN) — the checks the anti-false-OK oracle protects.
func dd2MutationFixture() string {
	return filepath.Join(srcpath.RepoRoot(), "fixtures", "replay-fidelity", "debian13-vmware-unsynced.tar.gz")
}

// sanitizeNoise strips every ASCII letter and digit from s, so spliced noise can
// never form a parseable record (the soundness guarantee — see the file header).
func sanitizeNoise(s string) string {
	var b strings.Builder
	for _, r := range s {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') {
			continue
		}
		b.WriteRune(r)
	}
	return b.String()
}

// damageBlob applies one information-destroying mutation to a blob's bytes.
// kind selects which; extra parameterizes offsets/noise only (never injects data).
func damageBlob(data []byte, kind int, extra string) []byte {
	switch kind % 7 {
	case 0: // truncate to empty
		return []byte{}
	case 1: // truncate to a prefix (drop a trailing portion of the recorded text)
		if len(data) == 0 {
			return data
		}
		cut := len(data) / 2
		if len(extra) > 0 {
			cut = int(extra[0]) % (len(data) + 1)
		}
		return append([]byte(nil), data[:cut]...)
	case 2: // garble every ASCII digit so any numeric field fails to parse
		out := append([]byte(nil), data...)
		for i, c := range out {
			if c >= '0' && c <= '9' {
				out[i] = 'x'
			}
		}
		return out
	case 3: // uppercase every ASCII letter (break case-sensitive key/token matches)
		return []byte(strings.ToUpper(string(data)))
	case 4: // replace the whole content with whitespace (present but no information)
		out := make([]byte, len(data))
		for i := range out {
			out[i] = ' '
		}
		return out
	case 5: // prepend a provably-non-data noise line
		return append([]byte(sanitizeNoise(extra)+"\n"), data...)
	default: // append provably-non-data noise
		return append(append([]byte(nil), data...), []byte("\n"+sanitizeNoise(extra))...)
	}
}

// dropFromIndex removes the index entry that references blobRel from an index.json
// body (files/index.json "blob", commands/index.json "stdout"/"stderr"), so the
// replay hits a recording gap for that path — the strongest information-removal.
// Returns the rewritten index and whether anything was dropped.
func dropFromIndex(indexJSON []byte, blobRel string) ([]byte, bool) {
	var entries []map[string]any
	if err := json.Unmarshal(indexJSON, &entries); err != nil {
		return indexJSON, false
	}
	kept := make([]map[string]any, 0, len(entries))
	dropped := false
	for _, e := range entries {
		if e["blob"] == blobRel || e["stdout"] == blobRel || e["stderr"] == blobRel {
			dropped = true
			continue
		}
		kept = append(kept, e)
	}
	if !dropped {
		return indexJSON, false
	}
	out, err := json.Marshal(kept)
	if err != nil {
		return indexJSON, false
	}
	return out, true
}

// readTree reads every regular file under dir into rel->bytes.
func readTree(dir string) (map[string][]byte, error) {
	tree := map[string][]byte{}
	err := filepath.Walk(dir, func(p string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.IsDir() {
			return nil
		}
		rel, err := filepath.Rel(dir, p)
		if err != nil {
			return err
		}
		data, err := os.ReadFile(p)
		if err != nil {
			return err
		}
		tree[filepath.ToSlash(rel)] = data
		return nil
	})
	return tree, err
}

// writeTree materializes tree into dir.
func writeTree(dir string, tree map[string][]byte) error {
	for rel, data := range tree {
		full := filepath.Join(dir, filepath.FromSlash(rel))
		if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
			return err
		}
		if err := os.WriteFile(full, data, 0o600); err != nil {
			return err
		}
	}
	return nil
}

// cacheKeyPrefixSentinel mirrors source.cacheKey's unexported namespace prefix
// ("\x00cached\x00"): Cached() entries (derived state dsd itself computes and
// writes into the bundle — e.g. clock/state, net/connectivity, lookpath/*) are
// stored as files under this prefix. They are NOT "captured files or command
// outputs" (the DD2 damage spec), so blobList excludes them from the damage set.
// Damaging a derived cache tests a different property (replay's behaviour when a
// computed cache is absent) — reported separately as a finding, not conflated
// with the raw-input anti-false-OK oracle.
const cacheKeyPrefixSentinel = "\x00cached\x00"

// cacheBlobs parses files/index.json and returns the set of blob rel-paths whose
// recorded path is in the Cached() namespace, so blobList can exclude them.
func cacheBlobs(tree map[string][]byte) map[string]bool {
	out := map[string]bool{}
	idx, ok := tree["files/index.json"]
	if !ok {
		return out
	}
	var entries []map[string]any
	if json.Unmarshal(idx, &entries) != nil {
		return out
	}
	for _, e := range entries {
		path, _ := e["path"].(string)
		blob, _ := e["blob"].(string)
		if blob != "" && strings.HasPrefix(path, cacheKeyPrefixSentinel) {
			out[blob] = true
		}
	}
	return out
}

// blobList returns the damageable blobs: every captured file blob and command
// output blob, EXCLUDING the derived-cache namespace (see cacheBlobs).
func blobList(tree map[string][]byte) []string {
	skip := cacheBlobs(tree)
	var blobs []string
	for rel := range tree {
		if skip[rel] {
			continue
		}
		if strings.HasPrefix(rel, "files/blobs/") || strings.HasPrefix(rel, "commands/blobs/") {
			blobs = append(blobs, rel)
		}
	}
	sort.Strings(blobs)
	return blobs
}

// dd2BaselineNonOK replays dir and returns name->status for every non-OK check.
func dd2BaselineNonOK(tb testing.TB, dir string) map[string]string {
	tb.Helper()
	b, err := source.Load(dir)
	if err != nil {
		tb.Fatalf("positive control: loading baseline bundle: %v", err)
	}
	results, insights, _ := replayBundle(b, false, true, false, false)
	m := verdictMap(results, insights)
	nonOK := map[string]string{}
	for name, status := range m {
		if status != "OK" {
			nonOK[name] = status
		}
	}
	return nonOK
}

// dd2ApplyDamage builds a damaged copy of baseTree under a fresh dir and returns
// it. sel picks the target blob; kind picks the mutation; a kind of 7 means
// "drop the blob's index entry" (recording gap) rather than garbling its bytes.
// Returns the dir and the rel path of the damaged blob.
func dd2ApplyDamage(dir string, baseTree map[string][]byte, blobs []string, sel, kind int, extra string) (string, string) {
	target := blobs[sel%len(blobs)]
	tree := make(map[string][]byte, len(baseTree))
	for k, v := range baseTree {
		tree[k] = v
	}
	if kind%8 == 7 {
		// Drop: remove the index entry referencing target and omit the blob.
		idxName := "files/index.json"
		if strings.HasPrefix(target, "commands/blobs/") {
			idxName = "commands/index.json"
		}
		if idx, ok := tree[idxName]; ok {
			if newIdx, dropped := dropFromIndex(idx, target); dropped {
				tree[idxName] = newIdx
				delete(tree, target)
			} else {
				// Nothing referenced it (shouldn't happen) — fall back to emptying.
				tree[target] = []byte{}
			}
		}
	} else {
		tree[target] = damageBlob(baseTree[target], kind, extra)
	}
	_ = writeTree(dir, tree)
	return dir, target
}

func FuzzCaptureReplayMutationRobustness(f *testing.F) {
	dd2CapParallelism()

	// Materialize the committed fixture to the raw-v1 on-disk layout ONCE, then
	// mutate per-iteration copies of that in-memory snapshot.
	b0, err := loadBundle(dd2MutationFixture())
	if err != nil {
		f.Fatalf("loading mutation fixture: %v", err)
	}
	baseDir := f.TempDir()
	if err := b0.Save(baseDir); err != nil {
		f.Fatalf("saving baseline bundle: %v", err)
	}
	baseTree, err := readTree(baseDir)
	if err != nil {
		f.Fatalf("reading baseline tree: %v", err)
	}
	blobs := blobList(baseTree)
	if len(blobs) == 0 {
		f.Fatalf("positive control: baseline bundle has no file/command blobs to damage")
	}

	// POSITIVE CONTROL: the undamaged baseline must have ≥1 non-OK check, else the
	// anti-false-OK oracle is vacuous.
	baselineNonOK := dd2BaselineNonOK(f, baseDir)
	if len(baselineNonOK) == 0 {
		f.Fatalf("positive control: baseline fixture has no non-OK check — anti-false-OK oracle would be vacuous")
	}

	seeds := []struct {
		sel, kind int
		extra     string
	}{
		{0, 0, ""}, {1, 1, "\x7f"}, {2, 2, ""}, {3, 3, ""},
		{4, 4, ""}, {5, 5, "\x00\t==="}, {6, 6, " \x00 "}, {7, 7, ""},
	}
	for _, s := range seeds {
		f.Add(uint16(s.sel), uint8(s.kind), s.extra)
	}

	f.Fuzz(func(t *testing.T, selRaw uint16, kindRaw uint8, extra string) {
		sel := int(selRaw)
		kind := int(kindRaw)

		dir := t.TempDir()
		dd2ApplyDamage(dir, baseTree, blobs, sel, kind, extra)

		var damaged map[string]string
		start := time.Now()
		func() {
			defer func() {
				if r := recover(); r != nil {
					t.Fatalf("PANIC in replay of damaged bundle (sel=%d kind=%d extra=%q): %v", sel, kind, extra, r)
				}
			}()
			b, err := source.Load(dir)
			if err != nil {
				// A damaged bundle that fails to load loudly is fine (fail-closed);
				// it is NOT a false-OK. Nothing more to check this iteration.
				return
			}
			results, insights, _ := replayBundle(b, false, true, false, false)
			damaged = verdictMap(results, insights)
		}()
		if elapsed := time.Since(start); elapsed > mutationWorkCeiling {
			t.Fatalf("BOUNDED WORK: damaged replay took %s (> %s) sel=%d kind=%d", elapsed, mutationWorkCeiling, sel, kind)
		}
		if damaged == nil {
			return // load failed — fail-closed, not a false-OK
		}

		// ANTI-FALSE-OK: no baseline non-OK check may read "OK" after damage.
		for name, baseStatus := range baselineNonOK {
			got, present := damaged[name]
			if present && got == "OK" {
				t.Fatalf("FALSE-OK: check %q was %s on the undamaged baseline but replayed OK after information-destroying damage (sel=%d kind=%d extra=%q) — losing inputs must surface as unknown, not healthy",
					name, baseStatus, sel, kind, extra)
			}
		}
	})
}
