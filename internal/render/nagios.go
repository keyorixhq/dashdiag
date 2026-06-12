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

	switch {
	case len(crit) > 0:
		detail := fmt.Sprintf("%d critical", len(crit))
		if len(warn) > 0 {
			detail += fmt.Sprintf(", %d warning", len(warn))
		}
		all := append(append([]string{}, crit...), warn...)
		return fmt.Sprintf("DASHDIAG CRITICAL - %s: %s", detail, strings.Join(all, ", ")), 2
	case len(warn) > 0:
		return fmt.Sprintf("DASHDIAG WARNING - %d warning: %s", len(warn), strings.Join(warn, ", ")), 1
	default:
		return "DASHDIAG OK - all checks passed", 0
	}
}
