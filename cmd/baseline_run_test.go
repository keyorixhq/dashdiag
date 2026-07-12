package cmd

// baseline_run_test.go — covers runBaselineSave (a real terse health run +
// baseline.SaveGolden write, HOME redirected to t.TempDir()). runBaselineDiff
// is intentionally NOT exercised here: on success with no drift it falls
// through fine, but both the "baseline not found" branch and the
// "drift found" branch end in a direct os.Exit(1)/os.Exit(1) call, and
// runBaselineDiff runs a SECOND live health snapshot to diff against the
// first — on a real, if idle, system there is no guarantee the two live
// snapshots produce byte-identical statuses, so this could nondeterministically
// call os.Exit(1) mid-test-binary and abort every other test in the package.
// That's the "os.Exit path is legitimately untestable in this harness" carve-out.

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/keyorixhq/dashdiag/internal/baseline"
)

// TestRunBaselineSave is not t.Parallel(): it uses t.Setenv to redirect HOME,
// which Go's testing package forbids combining with parallel subtests.
func TestRunBaselineSave(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)

	out := captureStdout(t, func() {
		if err := runBaselineSave(nil, []string{"test-golden"}); err != nil {
			t.Fatalf("runBaselineSave: %v", err)
		}
	})
	if !strings.Contains(out, "test-golden") || !strings.Contains(out, "saved") {
		t.Errorf("expected a save confirmation naming the baseline, got:\n%s", out)
	}

	goldenFile := filepath.Join(home, ".dsd", "golden", "test-golden.json")
	if _, err := os.Stat(goldenFile); err != nil {
		t.Errorf("expected golden baseline written at %s, got: %v", goldenFile, err)
	}

	snap, err := baseline.LoadGolden("test-golden")
	if err != nil {
		t.Fatalf("LoadGolden after save: %v", err)
	}
	if len(snap.Checks) == 0 {
		t.Error("saved golden baseline should carry at least one check")
	}
}

// TestBaselineListCmd covers baselineListCmd's inline RunE (both the "no
// baselines yet" and "list saved names" branches). Not t.Parallel(): uses
// t.Setenv to redirect HOME.
func TestBaselineListCmd_Empty(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	out := captureStderr(t, func() {
		if err := baselineListCmd.RunE(baselineListCmd, nil); err != nil {
			t.Fatalf("baselineListCmd.RunE: %v", err)
		}
	})
	if !strings.Contains(out, "no golden baselines saved yet") {
		t.Errorf("an empty golden dir should say so on stderr, got: %q", out)
	}
}

func TestBaselineListCmd_ListsSavedNames(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	if err := baseline.SaveGolden(&baseline.Snapshot{Hostname: "h"}, "alpha"); err != nil {
		t.Fatal(err)
	}
	if err := baseline.SaveGolden(&baseline.Snapshot{Hostname: "h"}, "beta"); err != nil {
		t.Fatal(err)
	}
	out := captureStdout(t, func() {
		if err := baselineListCmd.RunE(baselineListCmd, nil); err != nil {
			t.Fatalf("baselineListCmd.RunE: %v", err)
		}
	})
	if !strings.Contains(out, "alpha") || !strings.Contains(out, "beta") {
		t.Errorf("expected both saved baseline names listed, got: %q", out)
	}
}
