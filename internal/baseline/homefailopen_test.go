package baseline

import (
	"path/filepath"
	"testing"
)

// TestHomeFailOpen_KnownViolations deterministically proves the three
// unguarded os.UserHomeDir() call sites documented as known violations
// KV-HOME-FAILOPEN-BASELINE / KV-HOME-FAILOPEN-GOLDEN /
// KV-HOME-FAILOPEN-SECBASELINE in cmd/knownviolations_test.go: with $HOME
// unset, baselineDir/goldenDir/SecurityBaselinePath each silently fail open
// to a CWD-relative ".dsd/..." path instead of refusing to resolve — the
// exact class the OTHER three $HOME-dependent call sites in the repo
// (internal/tips/state.go, internal/selfupdate/nudge.go,
// internal/store/jsonl.go) were deliberately hardened against.
//
// Not t.Parallel(): t.Setenv forbids it, and these three assertions share one
// HOME unset for the whole test.
func TestHomeFailOpen_KnownViolations(t *testing.T) {
	t.Setenv("HOME", "")

	cases := []struct {
		name string
		fn   func() string
		want string
	}{
		{"baselineDir", baselineDir, filepath.Join(".dsd", "baselines")},
		{"goldenDir", goldenDir, filepath.Join(".dsd", "golden")},
		{"SecurityBaselinePath", SecurityBaselinePath, filepath.Join(".dsd", "security-baseline.json")},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := c.fn()
			if filepath.IsAbs(got) {
				t.Errorf("%s() = %q with $HOME unset — want a CWD-relative path (proving the known fail-open), got an absolute one instead: the underlying bug may have been fixed, in which case remove this case and its KV-* entry in cmd/knownviolations_test.go", c.name, got)
			}
			if got != c.want {
				t.Errorf("%s() = %q, want %q (CWD-relative .dsd path) — the fail-open shape changed, update this test and the matching KV-* description", c.name, got, c.want)
			}
		})
	}
}
