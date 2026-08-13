package cmd

import (
	"strings"
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

// TestHealthFixGroups_StripsInjectedNewline is the regression guard for
// cmd-04-05: a "to fix:" hint built from host data (a process name via
// argv[0]/prctl, a device/mount path, an interface name — see
// internal/analysis/heuristics_*.go) could contain an embedded newline. Left
// unstripped, printHealthFixes would render that as a second line under the
// same "$" prompt block, invisible to a quick "review before running" glance
// but included verbatim if the operator copy-pastes the whole block — a
// hidden-command injection. The newline must not survive into the grouped
// command.
func TestHealthFixGroups_StripsInjectedNewline(t *testing.T) {
	insights := []models.Insight{
		{Level: "CRIT", Check: "Security", Hints: []string{"to fix: kill -9 1234\nrm -rf /  # hidden"}},
	}
	groups := healthFixGroups(insights)
	if len(groups) != 1 || len(groups[0].cmds) != 1 {
		t.Fatalf("groups = %+v, want exactly one group with one command", groups)
	}
	got := groups[0].cmds[0]
	if strings.ContainsAny(got, "\n\r") {
		t.Fatalf("cmds[0] = %q, must not contain a raw newline/carriage-return", got)
	}
	want := "kill -9 1234 rm -rf /  # hidden"
	if got != want {
		t.Errorf("cmds[0] = %q, want %q (newline replaced with a space)", got, want)
	}
}

// TestSanitizeFixCmd_StripsControlBytes covers sanitizeFixCmd directly: every
// C0 control byte and DEL must become a space (not vanish, so token
// boundaries survive), and the ESC byte specifically — the ANSI escape-
// sequence trigger — must be neutralized the same way.
func TestSanitizeFixCmd_StripsControlBytes(t *testing.T) {
	in := "ip link set\x1b[31meth0\x00 up\tnow"
	got := sanitizeFixCmd(in)
	if strings.ContainsAny(got, "\x1b\x00") {
		t.Fatalf("sanitizeFixCmd(%q) = %q, still contains a control byte", in, got)
	}
	want := "ip link set [31meth0  up now"
	if got != want {
		t.Errorf("sanitizeFixCmd(%q) = %q, want %q", in, got, want)
	}
}
