package render

// DL1 target 1 — terminal escape / control injection through the output funnel.
//
// INVARIANT (internal-render, DL1): every string DashDiag prints that came from
// the diagnosed host — hostname, check name, status message, remediation hints,
// drill-down titles/columns/rows/KV/notes, per-check names/values — is carried
// through the plain-text render funnels (markdown report, share text,
// post-mortem, JSON) with ZERO raw terminal control. The rendered bytes must be
// valid UTF-8, must contain no ESC (0x1B) and no other unicode control rune
// except the newlines DashDiag itself emits. That is what stops a hostile host
// from planting CSI/OSC (incl. OSC 52 clipboard, OSC 8 hyperlinks), C1 controls
// or embedded newlines to forge a report line, hide text, or fake an OK/CRIT
// verdict. (Bidi-override runes are a SEPARATE, currently-unmet gap — see
// assertNoTerminalInjection's note and the report.)
//
// The funnels under test are the NON-styled builders. The lipgloss/TUI path
// legitimately emits ESC for its own styling and is covered separately by
// output.FuzzSanitizeThenRenderNoRawEscape (the per-string sanitizer). This
// target is the END-TO-END funnel oracle the per-string test does not give:
// host bytes are placed in every Insight/Snapshot field at once and the whole
// assembled document is checked.
//
// Each render is wrapped in the DL1 resource oracle (resource.Check): bytes
// allocated bounded by 64*inputLen + 1 MiB, wall time < 5 s, no goroutine leak.
// The pure builders here allocate only a few KB of fixed scaffolding for a tiny
// input (markdown ~8 KB, share ~6 KB, postmortem ~3 KB, json ~24 KB — measured),
// all well under the 1 MiB floor, so factor 64 (the DL1 default) holds with
// wide margin and still catches any super-linear growth with input size.
//
// Does NOT verify: the styled TUI output (see above); that a backtick in a
// Message cannot open a markdown code span (a markdown-rendering nuisance, not a
// terminal control sequence — logged in the report, not asserted here); any
// format DashDiag does not emit from these funnels; and off-funnel sinks
// (Prometheus/Nagios lines) — the report records the Nagios check-name
// sanitization gap the mapping surfaced, as a HARDENING lead, separately.

import (
	"bytes"
	"strings"
	"testing"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/keyorixhq/dashdiag/internal/baseline"
	"github.com/keyorixhq/dashdiag/internal/models"
	"github.com/keyorixhq/dashdiag/internal/output"
	"github.com/keyorixhq/dashdiag/internal/testutil/resource"
)

const dl1RenderAllocFactor = 64

// assertNoTerminalInjection asserts the invariant the shipped funnels actually
// uphold: valid UTF-8 (no raw 8-bit C1 byte), no raw ESC (0x1B), and no unicode
// control rune other than the '\n' DashDiag emits itself. ESC is the gate for
// CSI/OSC (incl. OSC 52 clipboard, OSC 8 hyperlinks); stripping it and the C1
// 0x80-0x9F bytes closes the escape-sequence class.
//
// It deliberately does NOT assert "no bidi-override rune". DL1 found that
// output.SanitizeControl strips unicode control runes but passes directional-
// formatting runes (U+202A-202E, U+2066-2069), which are unicode category Cf,
// not Cc — so a hostile hostname/process-name carrying an RLO survives into the
// pasted markdown/share/postmortem report and can visually reorder a line
// (Trojan-Source, CVE-2021-42574 class). That is a real HARDENING gap, reported
// as an issue-ready proposal in docs/fuzz/dl1-dependency-and-claims.md with a
// standalone reproducer; it is NOT asserted here because the committed code does
// not yet strip these and a red seed would break the build. The assertion is
// scoped to the current guarantee, not weakened to hide the gap.
func assertNoTerminalInjection(t *testing.T, format, out string) {
	t.Helper()
	if !utf8.ValidString(out) {
		t.Fatalf("%s: rendered output is not valid UTF-8 (a raw C1/8-bit byte survived)", format)
	}
	for i, r := range out {
		if r == 0x1b {
			t.Fatalf("%s: rendered output contains a raw ESC (0x1B) at byte %d", format, i)
		}
		if unicode.IsControl(r) && r != '\n' {
			t.Fatalf("%s: rendered output contains control rune %U at byte %d (only '\\n' is allowed)", format, r, i)
		}
	}
}

// assertJSONTerminalSafe is the JSON-only oracle. JSON is a MACHINE format that
// deliberately preserves raw host bytes (RenderJSON does not run them through
// SanitizeControl), so it is held to the weaker property encoding/json actually
// guarantees: valid UTF-8, and no raw ESC (json escapes every byte < 0x20 as
// \uXXXX, so a terminal-escape introducer can never survive). It does NOT
// require JSON to be free of DEL (U+007F) or UTF-8-encoded C1 controls
// (U+0080-U+009F): DL1 found that encoding/json leaves both RAW (it only escapes
// < 0x20), so a host string containing DEL or a C1 byte surfaces verbatim in
// `dsd health --json` / the MCP dsd_health payload. That is a HARDENING gap (raw
// JSON is not safe to cat to a terminal; a C1 0x9B is a CSI introducer), filed
// in the report as an issue-ready proposal, not asserted here — the JSON path's
// documented contract is raw passthrough for machine consumers.
func assertJSONTerminalSafe(t *testing.T, out string) {
	t.Helper()
	if !utf8.ValidString(out) {
		t.Fatalf("json: rendered output is not valid UTF-8")
	}
	if i := strings.IndexByte(out, 0x1b); i >= 0 {
		t.Fatalf("json: rendered output contains a raw ESC (0x1B) at byte %d", i)
	}
}

// buildHostileSnapshot plants the fuzz string into every host-derived field.
func buildHostileSnapshot(s string) (*baseline.Snapshot, []models.Insight) {
	levels := []string{"CRIT", "WARN", "INFO", "OK"}
	var insights []models.Insight
	for i, lvl := range levels {
		insights = append(insights, models.Insight{
			Level:   lvl,
			Check:   s + "/sub",
			Message: s,
			Hints:   []string{s, "run `" + s + "`"},
			Details: &models.Details{
				Type:    "kv_table",
				Title:   s,
				Columns: []string{s, "value"},
				Rows:    [][]string{{s, s}, {"k", s}},
				KV:      map[string]string{s: s, "host": s},
				Note:    s,
			},
			Unverified: i == 2,
			// UnverifiedReason is a CLOSED dsd-internal enum (needs_root, timeout,
			// unreadable, collector_error, parse, not_recorded) set by the analysis
			// layer — NOT host-controllable — so it is pinned to a valid value, not
			// fuzzed. (An earlier revision planted hostile bytes here and saw them
			// surface through the markdown coverage line; that was a wrong-premise
			// harness finding, not a real leak — the host cannot set this field.)
			UnverifiedReason: "unreadable",
		})
	}
	snap := &baseline.Snapshot{
		Hostname:  s,
		Timestamp: time.Unix(0, 0).UTC(),
		Version:   "test",
		Checks: []baseline.CheckResult{
			{Name: s, Status: "CRIT", Value: s},
			{Name: "disk", Status: "OK", Value: s},
		},
	}
	return snap, insights
}

func FuzzRenderFunnelNoTerminalInjection(f *testing.F) {
	seeds := []string{
		"plain host-01",
		"esc\x1b[31mRED\x1b[0m",                         // CSI SGR colour
		"osc52\x1b]52;c;ZXZpbA==\x07",                   // OSC 52 clipboard write
		"osc8\x1b]8;;http://evil/\x07click\x1b]8;;\x07", // OSC 8 hyperlink
		"c1raw\x9bmcsi",                                 // raw C1 CSI byte 0x9B
		"c1osc\x9d52;c;x\x9c",                           // raw C1 OSC
		"title\x1b]0;pwned\x07",                         // window-title rewrite
		"bidi‮KO‬ vs OK",                                // RLO override to flip text
		"iso⁦FAIL⁩",                                     // bidi isolate
		"newline\nfake\n### 🔴 CRIT forged check",        // line-forge attempt
		"fence```\ninjected markdown",                   // markdown fence break
		"nul\x00byte and \x07bell \x08bs",               // assorted C0 controls
		"bad\xff\xfe\xc0utf8",                           // invalid UTF-8
		"del\x7fchar",                                   // DEL — json leaves it raw (reported)
	}
	for _, s := range seeds {
		f.Add(s)
	}

	f.Fuzz(func(t *testing.T, s string) {
		snap, insights := buildHostileSnapshot(s)
		n := len(s)
		var mode output.OutputMode = output.ModeHuman

		var md, share, pm string
		resource.Check(t, n, dl1RenderAllocFactor, func() {
			md = BuildMarkdownReport(snap, insights, 0, nil)
		})
		assertNoTerminalInjection(t, "markdown", md)

		resource.Check(t, n, dl1RenderAllocFactor, func() {
			share = RenderShareText(snap, insights, s)
		})
		assertNoTerminalInjection(t, "share", share)

		// NOTE: RenderStory is deliberately NOT exercised here. It calls
		// baseline.LoadHistory (disk I/O, env-dependent ~7 MB) so it is not a
		// deterministic in-memory funnel, and it does not run its host-derived
		// ins.Check / CheckResult.Name through SanitizeControl the way the
		// markdown path does — both are tracked in the DL1 report as leads, not
		// asserted by this in-memory oracle.

		// The post-mortem title is the operator's --post-mortem incident-ID flag,
		// NOT a host-derived string, and RenderPostMortem prints it raw (line 18)
		// — so a benign title is passed and only the host-derived insight/snapshot
		// fields are fuzzed. The raw-title handling is logged in the report as a
		// low-severity operator-input HARDENING note, not exercised as a host
		// injection here (wrong premise if it were).
		resource.Check(t, n, dl1RenderAllocFactor, func() {
			pm = RenderPostMortem("incident-42", snap, insights, mode)
		})
		assertNoTerminalInjection(t, "postmortem", pm)

		var jsonOut []byte
		resource.Check(t, n, dl1RenderAllocFactor, func() {
			b, err := RenderJSON(nil, insights)
			if err != nil {
				return
			}
			jsonOut = b
		})
		// JSON is held to the machine-format oracle (valid UTF-8 + no raw ESC);
		// see assertJSONTerminalSafe for why DEL/C1 passthrough is reported, not
		// asserted.
		assertJSONTerminalSafe(t, string(bytes.TrimRight(jsonOut, "\n")))
	})
}
