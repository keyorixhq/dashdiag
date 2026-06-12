package cmd

import (
	"testing"

	"github.com/keyorixhq/dashdiag/internal/models"
)

func TestHealthFixGroups(t *testing.T) {
	insights := []models.Insight{
		{Level: "CRIT", Check: "Disk", Hints: []string{"to inspect: df -h", "to fix: clear /var/log"}},
		{Level: "WARN", Check: "Swap", Hints: []string{"to fix:   sysctl -w vm.swappiness=10"}}, // extra spaces
		{Level: "WARN", Check: "Swap", Hints: []string{"to fix: sysctl -w vm.swappiness=10"}},   // dup → deduped
		{Level: "INFO", Check: "Drives", Hints: []string{"to fix: ignored (INFO)"}},             // INFO skipped
		{Level: "WARN", Check: "Network", Hints: []string{"to inspect: ss -s"}},                 // no to-fix → no group
	}
	groups := healthFixGroups(insights)

	if len(groups) != 2 {
		t.Fatalf("expected 2 groups (Disk, Swap), got %d: %+v", len(groups), groups)
	}
	// Order: first-seen (Disk before Swap).
	if groups[0].check != "Disk" || groups[1].check != "Swap" {
		t.Errorf("group order wrong: %+v", groups)
	}
	if len(groups[0].cmds) != 1 || groups[0].cmds[0] != "clear /var/log" {
		t.Errorf("Disk cmds wrong: %+v", groups[0].cmds)
	}
	// Swap: deduped to one, whitespace trimmed.
	if len(groups[1].cmds) != 1 || groups[1].cmds[0] != "sysctl -w vm.swappiness=10" {
		t.Errorf("Swap cmds wrong (dedupe/trim): %+v", groups[1].cmds)
	}
}

func TestHealthFixGroups_NoneWhenNoFixHints(t *testing.T) {
	insights := []models.Insight{
		{Level: "CRIT", Check: "X", Hints: []string{"to inspect: foo"}},
		{Level: "OK", Check: "Y", Hints: []string{"to fix: bar"}},
	}
	if g := healthFixGroups(insights); len(g) != 0 {
		t.Errorf("expected no groups, got %+v", g)
	}
}
