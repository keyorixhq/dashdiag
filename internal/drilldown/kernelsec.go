package drilldown

import (
	"context"
	"encoding/json"
	"fmt"
	"runtime"
	"sort"
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
	return buildPolicyTable(appArmorComplainProfiles(ctx), selinuxEnforceMode(ctx)), nil
}

// selinuxEnforceMode returns the global SELinux mode in lowercase
// ("enforcing"/"permissive"/"disabled"), or "" when SELinux is not present
// (getenforce absent or failed).
func selinuxEnforceMode(ctx context.Context) string {
	out, err := runCmd(ctx, "getenforce")
	if err != nil {
		return ""
	}
	return strings.ToLower(strings.TrimSpace(out))
}

// buildPolicyTable renders the "not in enforcing mode" detail from the two MAC
// signals that actually represent NON-enforcing policy:
//   - AppArmor profiles in complain mode
//   - SELinux running globally in permissive (or disabled) mode
//
// It deliberately does NOT enumerate SELinux booleans. A boolean set to "on" is
// a normal policy choice — most of the ~64 booleans that report "on" are
// default-on — not a relaxation of enforcement. The old code listed every
// on-boolean as "SELinux policy relaxed" under a "not in enforcing mode" header
// and appended an AppArmor `aa-status | grep complain` hint, so on a fully
// SELinux-enforcing host (getenforce=Enforcing) it claimed ~64 healthy policies
// were "not enforcing" and pointed at an AppArmor tool that does not apply.
// (Found on Fedora CoreOS, 2026-06-29.) The genuine non-enforcing SELinux state
// is permissive mode / permissive domains, captured here via the global mode.
func buildPolicyTable(appArmorComplain []string, selinuxMode string) *models.Details {
	var rows [][]string

	for _, profile := range appArmorComplain {
		rows = append(rows, []string{profile, "complain", "AppArmor profile not enforcing"})
	}

	switch selinuxMode {
	case "permissive":
		rows = append(rows, []string{"SELinux", "permissive", "global policy logs but does not enforce"})
	case "disabled":
		rows = append(rows, []string{"SELinux", "disabled", "no SELinux enforcement"})
	}

	if len(rows) == 0 {
		return nil
	}

	const maxRows = 5
	note := ""
	if len(rows) > maxRows {
		note = fmt.Sprintf("... and %d more — review AppArmor complain profiles (aa-status) and SELinux mode (getenforce)", len(rows)-maxRows)
		rows = rows[:maxRows]
	}

	return &models.Details{
		Type:    "policy_table",
		Title:   "Security policies not in enforcing mode",
		Columns: []string{"POLICY", "MODE", "NOTE"},
		Rows:    rows,
		Note:    note,
	}
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
	// Sort for a DETERMINISTIC order: doc.Profiles is a Go map, so without this the
	// complain list (and thus the "first N shown" KernelSec detail-table rows) came
	// out in a different order each run — non-byte-stable replay + spurious
	// `dsd diff` deltas on any host with AppArmor complain profiles. (Surfaced by a
	// deep capture/replay determinism check on pve01, 2026-06-18.)
	sort.Strings(names)
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
