package baseline

import (
	"fmt"
	"os"
)

// resolveHomeDir returns the current user's home directory, or an error if it
// cannot be determined. os.UserHomeDir() can fail (or, defensively, return an
// empty string on success) when $HOME is unset/unresolvable — a stripped
// cron/systemd/CI/container environment. Every $HOME-dependent path in this
// package MUST fail closed on that condition and never silently fall back to
// a CWD-relative path: a relative "./.dsd/..." resolves against whatever —
// possibly shared or attacker-writable — CWD dsd happens to run from,
// letting a planted symlink redirect a security-sensitive write (baseline
// snapshots, golden baselines, the security baseline). This mirrors the
// fail-closed pattern already used by internal/tips/state.go's
// stateFilePath(), internal/selfupdate/nudge.go's defaultCachePath(), and
// internal/store/jsonl.go's StorePath() — the single place that logic lives
// for this package, so baselineDir/goldenDir/SecurityBaselinePath don't each
// duplicate it.
func resolveHomeDir() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("resolving home directory: %w", err)
	}
	if home == "" {
		return "", fmt.Errorf("resolving home directory: $HOME is empty")
	}
	return home, nil
}
