package render

import (
	"fmt"
	"strings"

	"github.com/keyorixhq/dashdiag/internal/models"
	"github.com/keyorixhq/dashdiag/internal/runner"
)

// NagiosLine renders a single monitoring-plugin status line for
// `dsd health --nagios`, plus the matching exit code. It follows the Nagios
// plugin output spec ("<SERVICE> <STATUS> - <text>", exit 0/1/2/3) that
// Icinga, check_mk, Sensu and Naemon all consume — and which dsd's own exit
// codes already match (0 OK, 1 WARNING, 2 CRITICAL). This lets dsd drop straight
// into an existing monitoring setup as a check command, no wrapper script.
//
// Each affected subsystem is named once at its worst level (a CRIT subsystem is
// not also listed under warnings). UNKNOWN (3) is not produced here — a failed
// run surfaces as an error from the command, not a health verdict.
func NagiosLine(results []runner.Result, insights []models.Insight) (string, int) {
	var crit, warn []string
	critSeen := map[string]bool{}
	warnSeen := map[string]bool{}
	for _, ins := range insights {
		if ins.Level == "CRIT" && !critSeen[ins.Check] {
			critSeen[ins.Check] = true
			crit = append(crit, ins.Check)
		}
	}
	for _, ins := range insights {
		if ins.Level == "WARN" && !critSeen[ins.Check] && !warnSeen[ins.Check] {
			warnSeen[ins.Check] = true
			warn = append(warn, ins.Check)
		}
	}

	// internal-render-03-03: a collector that errors (r.Err != nil) never becomes
	// a CRIT/WARN insight — ApplyThresholds only emits an INFO "check could not
	// run" disclosure for it (see internal/analysis), which every OTHER renderer
	// (the live table, --report, --report-html) already accounts for. This
	// renderer only ever inspected `insights` for CRIT/WARN, so a run where every
	// collector failed (nothing to derive a finding from, hence zero CRIT/WARN)
	// still printed a clean "DASHDIAG OK - all checks passed" to Icinga/Nagios/
	// check_mk — the exact false-OK a monitoring plugin must never emit.
	var failed []string
	failedSeen := map[string]bool{}
	for _, r := range results {
		if r.Err != nil && !failedSeen[r.Name] {
			failedSeen[r.Name] = true
			failed = append(failed, r.Name)
		}
	}

	switch {
	case len(crit) > 0:
		detail := fmt.Sprintf("%d critical", len(crit))
		if len(warn) > 0 {
			detail += fmt.Sprintf(", %d warning", len(warn))
		}
		if len(failed) > 0 {
			detail += fmt.Sprintf(", %d check(s) failed to run", len(failed))
		}
		all := append(append([]string{}, crit...), warn...)
		all = append(all, failed...)
		return fmt.Sprintf("DASHDIAG CRITICAL - %s: %s", detail, strings.Join(all, ", ")), 2
	case len(warn) > 0:
		detail := fmt.Sprintf("%d warning", len(warn))
		all := append([]string{}, warn...)
		if len(failed) > 0 {
			detail += fmt.Sprintf(", %d check(s) failed to run", len(failed))
			all = append(all, failed...)
		}
		return fmt.Sprintf("DASHDIAG WARNING - %s: %s", detail, strings.Join(all, ", ")), 1
	case len(failed) > 0:
		return fmt.Sprintf("DASHDIAG WARNING - %d check(s) failed to run: %s", len(failed), strings.Join(failed, ", ")), 1
	default:
		return "DASHDIAG OK - all checks passed", 0
	}
}
