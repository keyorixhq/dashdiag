//go:build taintoverlay

package baseline

// Input-to-sink taint harness for baseline names/hostnames (see
// internal/fuzzutil/taint). `dsd baseline save/diff <name>` and snapshot
// hostnames from untrusted manifests reach filenames. Contract: every file the
// baseline package touches lies under $HOME (set to a temp dir here); a path
// that escapes it, or any command/host/query flow, is unexpected.
//
// Run: go test -tags taintoverlay -overlay <taintoverlay dir>/overlay.json \
//        -vet=off -run '^$' -fuzz FuzzTaintBaselineNames ./internal/baseline

import (
	"path/filepath"
	"testing"

	"github.com/keyorixhq/dashdiag/internal/fuzzutil/taint"
)

func FuzzTaintBaselineNames(f *testing.F) {
	f.Add("golden", "host", uint8(0))
	f.Fuzz(func(t *testing.T, name, host string, mode uint8) {
		taint.RequireOverlay(t.Fatalf)
		taint.Reset()
		taint.ResetRules()
		home := t.TempDir()
		t.Setenv("HOME", home)
		taint.Allow(taint.Rule{Class: taint.Path, Root: home, Why: "baseline files live under $HOME"})
		defer taint.Check(t.Fatalf)
		n, h := taint.PathStr(name), taint.PathStr(host)
		if mode%2 == 1 {
			n, h = taint.Str(name), taint.Str(host)
		}
		snap := &Snapshot{Hostname: h}
		_ = SaveGolden(snap, n)
		_, _ = LoadGolden(n)
		_ = SaveBaseline(snap)
		_, _ = LoadBaseline(filepath.Join(home, "b.json")) // LoadBaseline's own argument is a path by contract: not tainted
		_, _ = FindBaselineBeforeTime(snap.Timestamp, h)
		_, _ = ListGolden()
	})
}
