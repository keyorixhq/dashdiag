package cmd

import (
	"github.com/keyorixhq/dashdiag/internal/analysis"
	"github.com/keyorixhq/dashdiag/internal/models"
	"github.com/keyorixhq/dashdiag/internal/platform"
	"github.com/keyorixhq/dashdiag/internal/runner"
)

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
func recordWorstInsight(insights []models.Insight) {
	for _, ins := range insights {
		switch ins.Level {
		case "CRIT":
			recordExitCode(2)
		case "WARN":
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
