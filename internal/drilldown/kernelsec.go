package drilldown

import (
	"context"
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
		// Try plain aa-status
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

	// Check SELinux booleans that might be relevant
	seboolOut, _ := runCmd(ctx, "getsebool", "-a")
	for _, line := range strings.Split(seboolOut, "\n") {
		if strings.Contains(line, " off") {
			parts := strings.SplitN(line, " --> ", 2)
			if len(parts) == 2 {
				rows = append(rows, []string{parts[0], "off", "SELinux boolean"})
			}
		}
	}

	if len(rows) == 0 {
		return nil, nil
	}

	return &models.Details{
		Type:    "policy_table",
		Title:   "Security policies not in enforcing mode",
		Columns: []string{"POLICY", "MODE", "NOTE"},
		Rows:    rows,
	}, nil
}
