package render

// DD-VERDICT-2 Part C — terminal escape / control injection through the STORY
// narration funnels, the render entry points FuzzRenderFunnelNoTerminalInjection
// (DL1, dl1_render_escape_fuzz_test.go) deliberately left open.
//
// DL1 excluded RenderStory because its PUBLIC entry (RenderStory) calls
// baseline.LoadHistory — disk I/O, not a deterministic in-memory funnel — and
// tracked it as a leftover lead. But the TWO builders that actually assemble the
// narration, renderStorySinglePoint and renderStoryFromHistory, take their inputs
// as plain arguments and touch no disk; they are reachable deterministically and
// are exactly where host-derived strings (hostname, check name, message, per-check
// name/value, and the /proc/PID/comm zombie-offender name) are formatted for the
// terminal. This target drives BOTH end to end, planting hostile bytes into every
// such field at once, and asserts the same invariant every other DashDiag funnel
// upholds (assertNoTerminalInjection, shared with the DL1 target): valid UTF-8, no
// raw ESC (the CSI/OSC/OSC-52/OSC-8 gate), no C1 control byte, no unicode control
// rune except the '\n' DashDiag emits itself, and no bidi-formatting rune
// (Trojan-Source / CVE-2021-42574 class).
//
// Existing coverage this complements: dl1_sink_sanitize_test.go unit-tests
// renderStorySinglePoint / renderStoryFromHistory sanitize ins.Check / c.Name on a
// couple of FIXED hostile strings; this is the fuzzed, all-fields-at-once,
// full-hostile-corpus (incl. bidi/OSC/C1) version, and it also exercises the
// floored "unverified checks" branch, the current-issues branch, and the
// Processes zombie-offender path (extractZombieOffender).
//
// CheckResult.Status is planted too: renderStoryFromHistory prints the event's
// resulting status (e.to) at both print sites, and a stored baseline snapshot is
// attacker-influenced, so a hostile Status must be sanitised like c.Name and c.Value.
// The oracle originally pinned Status to the WARN/CRIT/OK enum because the raw print
// made it red on shipped code; the fix (output.SanitizeControl in storyEvents) landed
// in the same change and the pin was removed.
//
// Does NOT verify: the styled lipgloss/TUI story path, if any (the plain-text builders are the sink here);
// bounded work / allocation (DL1 and TU1 carry the resource oracle for the render
// package; this target is injection-only); any narration format RenderStory does not
// emit from these two builders; and the on-disk history-load path itself (the inputs
// are supplied in memory).

import (
	"strings"
	"testing"
	"time"

	"github.com/keyorixhq/dashdiag/internal/baseline"
	"github.com/keyorixhq/dashdiag/internal/models"
)

// storyEscapeSeeds are the hostile-byte corpus, the terminal-escape classes DL1
// enumerated: raw CSI, OSC 52 clipboard, OSC 8 hyperlink, raw C1 introducers,
// window-title rewrite, bidi override/isolate, line-forge, assorted C0, invalid
// UTF-8, and DEL.
var storyEscapeSeeds = []string{
	"plain host-01",
	"esc\x1b[31mRED\x1b[0m",
	"osc52\x1b]52;c;ZXZpbA==\x07",
	"osc8\x1b]8;;http://evil/\x07click\x1b]8;;\x07",
	"c1raw\x9bmcsi",
	"title\x1b]0;pwned\x07",
	"bidi\u202eKO\u202c vs OK",
	"iso\u2066FAIL\u2069",
	"newline\nfake\n### forged",
	"nul\x00byte and \x07bell \x08bs",
	"bad\xff\xfe\xc0utf8",
	"del\x7fchar",
}

// buildStoryInsights plants s into the host-derived Insight fields the single-point
// builder prints (Check, Message), across the active (WARN/CRIT) and the floored
// "unverified" branches (renderStorySinglePoint story.go:43-46 and :57).
func buildStoryInsights(s string) []models.Insight {
	return []models.Insight{
		{Level: "CRIT", Check: s + "/sub", Message: s},
		{Level: "WARN", Check: "mem/" + s, Message: s},
		{Level: "OK", Check: s, Message: s, Unverified: true, UnverifiedReason: "unreadable"},
	}
}

// buildStoryHistory plants s into CheckResult.Name/Value/Raw across two snapshots so
// renderStoryFromHistory exercises: an events line (status CHANGE on check "X"), the
// current-issues branch (a WARN/CRIT check in the last snapshot), and the Processes
// zombie-offender path (extractZombieOffender pulls parent_name from Raw), and a
// status change on check "Y" whose resulting Status is the hostile string itself.
func buildStoryHistory(s string) []*baseline.Snapshot {
	zombieRaw := map[string]any{
		"zombie_procs": []any{map[string]any{"parent_name": s}},
	}
	return []*baseline.Snapshot{
		{
			Hostname:  s,
			Timestamp: time.Unix(0, 0).UTC(),
			Checks: []baseline.CheckResult{
				{Name: "X/" + s, Status: "OK", Value: s},
				{Name: "Processes", Status: "OK", Value: s},
				{Name: "Y", Status: "OK", Value: "v"},
			},
		},
		{
			Hostname:  s,
			Timestamp: time.Unix(3600, 0).UTC(),
			Checks: []baseline.CheckResult{
				{Name: "X/" + s, Status: "CRIT", Value: s},
				{Name: "Processes", Status: "CRIT", Value: s, Raw: zombieRaw},
				{Name: "Y", Status: s, Value: "v"},
			},
		},
	}
}

func FuzzRenderStoryNoTerminalInjection(f *testing.F) {
	// Positive control: the two builders must actually emit the host-derived fields,
	// so the oracle can never pass vacuously. A plain hostname must appear in the
	// single-point head line, and a plain check name in the from-history events.
	{
		snap := &baseline.Snapshot{Hostname: "posctl-host", Timestamp: time.Unix(0, 0).UTC()}
		out := renderStorySinglePoint(buildStoryInsights("posctl"), snap)
		if !strings.Contains(out, "posctl") {
			f.Fatalf("positive control: single-point story did not surface the planted host string — the oracle would be vacuous")
		}
		h := buildStoryHistory("posctl")
		if !strings.Contains(renderStoryFromHistory(h), "posctl") {
			f.Fatalf("positive control: from-history story did not surface the planted host string — the oracle would be vacuous")
		}
	}

	for _, s := range storyEscapeSeeds {
		f.Add(s)
	}

	f.Fuzz(func(t *testing.T, s string) {
		snap := &baseline.Snapshot{
			Hostname:  s,
			Timestamp: time.Unix(0, 0).UTC(),
			Checks: []baseline.CheckResult{
				{Name: s, Status: "CRIT", Value: s},
			},
		}
		assertNoTerminalInjection(t, "story-single", renderStorySinglePoint(buildStoryInsights(s), snap))
		assertNoTerminalInjection(t, "story-history", renderStoryFromHistory(buildStoryHistory(s)))
	})
}
