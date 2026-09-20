package baseline

import (
	"os"
	"testing"
)

// TestHomeFailClosed proves the fix for the three $HOME-fail-open bugs
// formerly tracked as KV-HOME-FAILOPEN-BASELINE / KV-HOME-FAILOPEN-GOLDEN /
// KV-HOME-FAILOPEN-SECBASELINE (cmd/knownviolations_test.go — those entries
// are deleted in the same change that introduces this test, since the
// underlying bypass no longer exists to tolerate).
//
// With $HOME unset/unresolvable, baselineDir/goldenDir/SecurityBaselinePath
// must fail CLOSED — return a non-nil error — instead of silently resolving
// to a CWD-relative ".dsd/..." path the way they used to. This mirrors the
// fail-closed contract already enforced by internal/tips/state.go's
// stateFilePath(), internal/selfupdate/nudge.go's defaultCachePath(), and
// internal/store/jsonl.go's StorePath() (see resolveHomeDir's doc comment in
// homedir.go, which all three of THIS package's call sites now share).
//
// Not t.Parallel(): t.Setenv forbids it, and these assertions share one HOME
// unset for the whole test.
func TestHomeFailClosed(t *testing.T) {
	t.Setenv("HOME", "")

	t.Run("baselineDir", func(t *testing.T) {
		got, err := baselineDir()
		if err == nil {
			t.Fatalf("baselineDir() = %q, <nil> with $HOME unset — want a non-nil error, not a resolved path (proves fail-closed)", got)
		}
	})
	t.Run("goldenDir", func(t *testing.T) {
		got, err := goldenDir()
		if err == nil {
			t.Fatalf("goldenDir() = %q, <nil> with $HOME unset — want a non-nil error, not a resolved path (proves fail-closed)", got)
		}
	})
	t.Run("SecurityBaselinePath", func(t *testing.T) {
		got, err := SecurityBaselinePath()
		if err == nil {
			t.Fatalf("SecurityBaselinePath() = %q, <nil> with $HOME unset — want a non-nil error, not a resolved path (proves fail-closed)", got)
		}
	})
}

// TestHomeFailClosed_NoCWDWrites proves the fail-closed fix has real teeth:
// with $HOME unset, the three Save* entry points must refuse to write
// ANYTHING under the current working directory (the exact bug — a
// CWD-relative ".dsd/..." write — that the old fail-open let through). A CWD
// with nothing but the working directory itself before and after each call is
// the strongest available proof of "does not write anywhere" from outside the
// package.
func TestHomeFailClosed_NoCWDWrites(t *testing.T) {
	t.Setenv("HOME", "")
	cwd := t.TempDir()
	t.Chdir(cwd)

	assertCWDEmpty := func(t *testing.T, label string) {
		t.Helper()
		entries, err := os.ReadDir(cwd)
		if err != nil {
			t.Fatalf("reading cwd after %s: %v", label, err)
		}
		if len(entries) != 0 {
			t.Fatalf("%s wrote to CWD with $HOME unset: %v", label, entries)
		}
	}

	hostname, _ := os.Hostname()
	snap := &Snapshot{Hostname: hostname, Version: "v1"}

	if err := SaveBaseline(snap); err == nil {
		t.Error("SaveBaseline should fail closed (return an error) when $HOME is unset")
	}
	assertCWDEmpty(t, "SaveBaseline")

	if err := SaveGolden(snap, "prod"); err == nil {
		t.Error("SaveGolden should fail closed (return an error) when $HOME is unset")
	}
	assertCWDEmpty(t, "SaveGolden")

	if err := SaveSecurityBaseline(&SecurityBaseline{Hostname: hostname}); err == nil {
		t.Error("SaveSecurityBaseline should fail closed (return an error) when $HOME is unset")
	}
	assertCWDEmpty(t, "SaveSecurityBaseline")
}

// TestHomeFailClosed_PathHelpersPropagate proves the lower-level path helpers
// that funnel into baselineDir/goldenDir (latestPath, prevPath, goldenPath)
// propagate the fail-closed error rather than swallowing it and returning a
// zero-value/CWD-relative path.
func TestHomeFailClosed_PathHelpersPropagate(t *testing.T) {
	t.Setenv("HOME", "")

	if _, err := latestPath("host"); err == nil {
		t.Error("latestPath should propagate the fail-closed error when $HOME is unset")
	}
	if _, err := prevPath("host"); err == nil {
		t.Error("prevPath should propagate the fail-closed error when $HOME is unset")
	}
	if _, err := goldenPath("prod"); err == nil {
		t.Error("goldenPath should propagate the fail-closed error when $HOME is unset")
	}
}
