package cmd

import (
	"errors"

	"github.com/keyorixhq/dashdiag/internal/analysis"
	"github.com/keyorixhq/dashdiag/internal/models"
	"github.com/keyorixhq/dashdiag/internal/platform"
	"github.com/keyorixhq/dashdiag/internal/runner"
)

// fatalPreflightError marks an error that happened before any collector ran
// — a bad --policy file, a config load failure — as distinct from an
// ordinary command error (bad flags, unknown subcommand) and from a real
// WARN/CRIT finding. Execute() maps it to exit code 3 (UNKNOWN), reserved
// for "no meaningful verdict at all", rather than the generic exit 1 every
// other Cobra dispatch error gets — 1 already means WARN for `dsd health`,
// and colliding the two would make a broken policy file indistinguishable
// from a real finding to anything gating on exit code.
type fatalPreflightError struct{ err error }

func (e *fatalPreflightError) Error() string { return e.err.Error() }
func (e *fatalPreflightError) Unwrap() error { return e.err }

// fatalPreflight wraps err as a fatalPreflightError, or returns nil
// unchanged so `return fatalPreflight(err)` composes with the usual
// `if err != nil` idiom without an extra nil check at call sites.
func fatalPreflight(err error) error {
	if err == nil {
		return nil
	}
	return &fatalPreflightError{err: err}
}

// exitCodeForExecuteError maps a top-level Cobra dispatch error to a process
// exit code. See fatalPreflightError's doc comment for why 3 is reserved and
// scoped this narrowly rather than applied to every command error.
func exitCodeForExecuteError(err error) int {
	var fatal *fatalPreflightError
	if errors.As(err, &fatal) {
		return 3
	}
	return 1
}

// pendingExitCode holds the worst severity observed during a standalone
// subcommand run, mapped to the documented dsd convention (2 = any CRIT,
// 1 = any WARN, 0 = clean). Execute() applies it after the command returns so
// deferred cleanup (progress bars, --out redirection) still runs — unlike a
// mid-command os.Exit, which skips defers.
//
// Fixes BUG-022: standalone subcommands (disk, security, docker, k8s, cve, …)
// rendered severity correctly but always exited 0, breaking the documented
// CI/CD exit-code contract that only `dsd health` and `dsd tls` honoured. A
// pipeline gating on `dsd disk` would report success on, e.g., a DEGRADED ZFS
// pool. Recording severity here applies the same worst-insight→exit mapping
// `dsd health` uses, so the standalone subcommands agree with it.
var pendingExitCode int

// recordExitCode raises the pending exit code to at least code.
func recordExitCode(code int) {
	if code > pendingExitCode {
		pendingExitCode = code
	}
}

// recordWorstInsight maps the worst level among insights to the exit convention
// (CRIT → 2, WARN → 1) and records it.
//
// C1: an Unverified insight (the check could not be determined — permission
// denied, a collector error, a read that failed) floors the exit code at
// WARN(1) even when its Level is a downgraded INFO, which never raises the
// exit code on its own. Kept in lockstep with
// internal/render/health.go's exitCodeFromInsights — see that function's doc
// comment for the full reasoning (why the floor stops at WARN, not higher).
func recordWorstInsight(insights []models.Insight) {
	for _, ins := range insights {
		switch ins.Level {
		case "CRIT":
			recordExitCode(2)
		case "WARN":
			recordExitCode(1)
		}
		if ins.Unverified {
			recordExitCode(1)
		}
	}
}

// recordResultSeverity runs collected results through the shared health
// heuristics and records the worst severity, so a standalone subcommand exits
// with the same code `dsd health` would for the same findings. Container and
// cloud context are detected here to keep call sites to a single argument; the
// cost is one cheap probe per command invocation.
func recordResultSeverity(results []runner.Result) {
	ctrCtx := platform.DetectContainerContext()
	cloudEnv := platform.DetectCloudEnvironment()
	thresh := analysis.DefaultThresholds(cloudEnv)
	recordWorstInsight(analysis.ApplyThresholds(results, thresh, cloudEnv, ctrCtx))
}
