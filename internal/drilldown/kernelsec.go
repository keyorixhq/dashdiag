package drilldown

import (
	"context"
	"encoding/json"
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

	// Check AppArmor profiles in complain mode (BUG-023).
	for _, profile := range appArmorComplainProfiles(ctx) {
		rows = append(rows, []string{profile, "complain", "AppArmor profile not enforcing"})
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

// appArmorComplainProfiles returns the names of AppArmor profiles in complain
// mode. It prefers `aa-status --pretty-json` (parsed as real JSON) and falls
// back to the plain `aa-status` text. The previous implementation grepped the
// JSON output line-by-line for "complain", capturing the surrounding JSON
// punctuation verbatim (`"Xorg": "complain",` instead of `Xorg`) — BUG-023.
func appArmorComplainProfiles(ctx context.Context) []string {
	if out, err := runCmd(ctx, "aa-status", "--pretty-json"); err == nil && out != "" {
		if names, ok := parseAAStatusJSON(out); ok {
			return names
		}
	}
	// Fallback: plain `aa-status` text — older releases lack --pretty-json, and
	// the JSON parse may fail on an unexpected schema.
	out, _ := runCmd(ctx, "aa-status")
	return parseAAStatusText(out)
}

// parseAAStatusJSON extracts complain-mode profile names from the JSON emitted
// by `aa-status --pretty-json`, whose top-level "profiles" key maps each
// profile name to its mode ("enforce" / "complain" / ...). The bool is false
// when the output is not the expected JSON shape, so the caller can fall back.
func parseAAStatusJSON(out string) ([]string, bool) {
	var doc struct {
		Profiles map[string]string `json:"profiles"`
	}
	if err := json.Unmarshal([]byte(out), &doc); err != nil || doc.Profiles == nil {
		return nil, false
	}
	var names []string
	for name, mode := range doc.Profiles {
		if mode == "complain" {
			names = append(names, name)
		}
	}
	return names, true
}

// parseAAStatusText extracts complain-mode profile names from plain `aa-status`
// output. The text is sectioned: a header line "N profiles are in complain
// mode." is followed by one indented profile name per line until the next
// header. Process sections ("M processes are in ... mode.") end the run.
func parseAAStatusText(out string) []string {
	var names []string
	inComplain := false
	for _, line := range strings.Split(out, "\n") {
		trimmed := strings.TrimSpace(line)
		switch {
		case strings.Contains(trimmed, "profiles are in complain mode"):
			inComplain = true
		case strings.Contains(trimmed, "are in ") && strings.HasSuffix(trimmed, "mode."),
			strings.HasSuffix(trimmed, "are loaded."),
			strings.HasSuffix(trimmed, "is loaded."):
			// Any other section header ends the complain run.
			inComplain = false
		case inComplain && trimmed != "":
			names = append(names, trimmed)
		}
	}
	return names
}
