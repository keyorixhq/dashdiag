package drilldown

import (
	"context"
	"fmt"
	"runtime"
	"strings"

	"github.com/keyorixhq/dashdiag/internal/models"
)

// PoliciesNotEnforcing lists security policies that are not in enforcing mode.
func PoliciesNotEnforcing(ctx context.Context) (*models.Details, error) {
	if runtime.GOOS == "darwin" {
		return nil, nil
	}
	return policiesLinux(ctx)
}

func policiesLinux(ctx context.Context) (*models.Details, error) {
	var rows [][]string

	// Check AppArmor profiles in complain mode
	aaOut, err := runCmd(ctx, "aa-status", "--pretty-json")
	if err != nil {
		aaOut, _ = runCmd(ctx, "aa-status")
	}
	if aaOut != "" {
		for _, line := range strings.Split(aaOut, "\n") {
			if strings.Contains(line, "complain") {
				profile := strings.TrimSpace(line)
				rows = append(rows, []string{profile, "complain", "AppArmor profile not enforcing"})
			}
		}
	}

	// Check SELinux booleans explicitly set to ON — these are relaxed policies
	// and worth surfacing. "off" booleans are the normal default for 200+ booleans
	// and produce useless noise; we never list them.
	seboolOut, _ := runCmd(ctx, "getsebool", "-a")
	for _, line := range strings.Split(seboolOut, "\n") {
		if strings.Contains(line, " on") {
			parts := strings.SplitN(line, " --> ", 2)
			if len(parts) == 2 && strings.TrimSpace(parts[1]) == "on" {
				rows = append(rows, []string{strings.TrimSpace(parts[0]), "on", "SELinux policy relaxed"})
			}
		}
	}

	if len(rows) == 0 {
		return nil, nil
	}

	const maxRows = 5
	note := ""
	if len(rows) > maxRows {
		note = fmt.Sprintf("... and %d more — run: aa-status | grep complain", len(rows)-maxRows)
		rows = rows[:maxRows]
	}

	return &models.Details{
		Type:    "policy_table",
		Title:   "Security policies not in enforcing mode",
		Columns: []string{"POLICY", "MODE", "NOTE"},
		Rows:    rows,
		Note:    note,
	}, nil
}
