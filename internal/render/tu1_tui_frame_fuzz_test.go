package render

// TU1 target A — the assembled lipgloss/TUI terminal frame carries no host ESC.
//
// INVARIANT (internal-render, TU1): every host-derived string DashDiag prints to
// the terminal through its STYLED `dsd health` funnel — hostname, check name,
// status message, remediation hints, Details title/columns/rows/KV/note, and the
// inline per-row summary (which surfaces collector fields such as GPU/disk/iface
// names) — contributes ZERO terminal control of its own to the assembled frame.
// The ONLY escape sequences in the frame are DashDiag's own CSI-SGR styling
// (Foreground/Bold/Faint via lipgloss); a hostile host cannot plant a CSI/OSC
// (incl. OSC 52 clipboard, OSC 8 hyperlink), a C1 control, or an embedded newline
// that forges a report line, clears the screen, or fakes an OK/CRIT verdict.
//
// This is the END-TO-END STYLED-FRAME oracle DL1 left as leftover #3 ("prove host
// bytes contribute no ESC of their own to the styled output … needs a way to diff
// dsd's own ESC from host ESC"). DL1's FuzzRenderFunnelNoTerminalInjection covers
// the NON-styled funnels (markdown/share/post-mortem/JSON); output.FuzzSanitize
// ThenRenderNoRawEscape covers the per-string sanitizer. Neither drives the real
// styled Renderer that `dsd health` prints to a terminal. This target does.
//
// HOW host ESC is told apart from dsd's own ESC — without guessing (verified by a
// probe, see the TU1 report): render the SAME hostile frame twice through the real
// Renderer under two forced lipgloss color profiles.
//
//   - termenv.Ascii: lipgloss emits NONE of its own styling ESC, yet passes any
//     ESC already present in the (post-SanitizeControl) content straight through.
//     So under Ascii the frame's dsd-contributed ESC count is exactly zero, and
//     ANY ESC or non-newline control rune that appears is host-contributed — i.e.
//     a sanitize-choke-point gap. This is the PRIMARY oracle (assertFrameClean),
//     and it catches every escape FORM: CSI-SGR, CSI-non-m (e.g. ESC[2J), OSC,
//     and raw/encoded C1.
//   - termenv.TrueColor: lipgloss wraps styled spans in CSI-SGR (ESC '[' … 'm').
//     Stripping exactly that grammar (sgrRe) must reproduce the Ascii frame
//     byte-for-byte — proving dsd's own escapes are well-formed SGR and the styled
//     path introduced nothing else. This is the SECONDARY consistency check.
//
// Each render is wrapped in the DL1 shared resource oracle (resource.Check):
// bytes allocated bounded by factor*inputLen + 1 MiB and wall time < 5 s. factor
// is 8192 (NOT the DL1 default of 64) and the resource oracle here is DELIBERATELY
// LOOSE: the fixture fans one fuzz string into ~25 styled fields across three
// insights, a Details block and the snapshot, so per-input-byte amplification is
// dominated by that fixture fan-out (LINEAR in input size), not a funnel defect.
// The resource oracle is a gross-pathology / hang backstop; the injection check is
// the primary oracle. (Same calibration rationale as the DL1 sibling target.)
//
// SERIALISATION: os.Stdout and the lipgloss default color profile are process
// globals. Under -parallel 2 two fuzz workers would clobber each other's captured
// frame and MemStats delta, so the whole render+capture+assert body holds
// tu1FrameMu — the same pattern RO1 used for its process-global exec/net globals.
//
// Does NOT verify (stated here, expanded in the report): the bubbletea key-input
// parser (SDK-internal, reads a live fd — not a dsd-held buffer; select.go's model
// logic is covered by the companion FuzzTUISelectModelKeyStream in
// internal/tui/tu1_tui_select_fuzz_test.go); the lipgloss/cellbuf DISPLAY-WIDTH path (production
// styles set no .Width()/.Align()/border, and renderDetails pads by BYTE length,
// so the upstream cellbuf width defects are not reachable from this frame — the
// report documents this); bidi-override REORDERING (U+202A-202E / U+2066-2069 are
// category Cf, pass SanitizeControl, and are a known HARDENING gap DL1 already
// filed — they are not terminal CONTROL, so this oracle neither asserts nor needs
// them); and whether the styled layout is visually correct (only that no host
// control byte survives).

import (
	"os"
	"regexp"
	"strings"
	"sync"
	"testing"
	"unicode"
	"unicode/utf8"

	"github.com/charmbracelet/lipgloss"
	"github.com/muesli/termenv"

	"github.com/keyorixhq/dashdiag/internal/baseline"
	"github.com/keyorixhq/dashdiag/internal/models"
	"github.com/keyorixhq/dashdiag/internal/output"
	"github.com/keyorixhq/dashdiag/internal/runner"
	"github.com/keyorixhq/dashdiag/internal/testutil/resource"
)

const tu1FrameAllocFactor = 8192

// tu1FrameMu serialises the render+capture+assert body — see the file header.
var tu1FrameMu sync.Mutex

// sgrRe matches a CSI SGR sequence: ESC '[' ; zero or more digits/semicolons ;
// 'm'. This is the ENTIRE escape grammar DashDiag's own styling emits.
var sgrRe = regexp.MustCompile("\x1b\\[[0-9;]*m")

// assertFrameClean is the PRIMARY oracle: the frame must be valid UTF-8, contain
// no raw ESC (0x1B) and no unicode control rune other than '\n' (DashDiag's own
// line breaks). Applied to the Ascii-profile frame, where dsd emits zero styling
// ESC, so anything it catches is host-contributed.
func assertFrameClean(t *testing.T, label, frame string) {
	t.Helper()
	if !utf8.ValidString(frame) {
		t.Fatalf("%s: frame is not valid UTF-8 (a raw C1/8-bit byte survived to the terminal)", label)
	}
	for i, r := range frame {
		if r == 0x1b {
			t.Fatalf("%s: frame contains a raw ESC (0x1B) at byte %d — host-contributed terminal control", label, i)
		}
		if unicode.IsControl(r) && r != '\n' {
			t.Fatalf("%s: frame contains control rune %U at byte %d (only '\\n' is allowed)", label, r, i)
		}
	}
}

// buildHostileFrame plants the fuzz string into every host-derived field of a
// snapshot, a set of insights (one per Details shape), and the matching collector
// results that drive the styled row path.
func buildHostileFrame(s string) (*baseline.Snapshot, []models.Insight, []runner.Result) {
	// Real-ish check names so insightForResult matches the results below and the
	// styled row path (printRow -> formatStatusLine) is exercised with a message.
	mk := func(level, check, dtype string) models.Insight {
		return models.Insight{
			Level:   level,
			Check:   check,
			Message: s,
			Hints:   []string{s, "to fix: run `" + s + "`"},
			Details: &models.Details{
				Type:    dtype,
				Title:   s,
				Columns: []string{s, "value"},
				Rows:    [][]string{{s, s}, {"k", s}},
				KV:      map[string]string{s: s, "host": s, "log_tail": s + "\nsecond\x1bline"},
				Note:    s,
			},
		}
	}
	insights := []models.Insight{
		mk("CRIT", "Memory", "kv_table"),
		mk("WARN", "Disk", "log_tail"),
		mk("INFO", "Network", "kv"),
	}
	snap := &baseline.Snapshot{
		Hostname: s,
		Version:  "test",
		Checks: []baseline.CheckResult{
			{Name: s, Status: "CRIT", Value: s},
			{Name: "Memory", Status: "OK", Value: s},
		},
	}
	// Results: three matching the insights above (message + Details rows) and one
	// with no insight ("Swap") so it renders an OK row whose inline summary is the
	// host string via inlineFn — the other styled host-text sink.
	results := []runner.Result{
		{Name: "Memory"}, {Name: "Disk"}, {Name: "Network"}, {Name: "Swap"},
	}
	return snap, insights, results
}

// renderFrameLocked renders the hostile frame through the real styled Renderer
// under the given color profile and returns the captured os.Stdout. The CALLER
// MUST hold tu1FrameMu. It drives the row path (PrintAllMock -> printRow ->
// formatStatusLine), every Details shape (renderDetails), and the summary
// (PrintSummary -> verdict banner, printInsightGroup, hints, coverage).
func renderFrameLocked(t *testing.T, profile termenv.Profile, snap *baseline.Snapshot, insights []models.Insight, results []runner.Result) string {
	t.Helper()
	oldProfile := lipgloss.ColorProfile()
	lipgloss.SetColorProfile(profile)
	defer lipgloss.SetColorProfile(oldProfile)

	oldStdout := os.Stdout
	rd, wr, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	os.Stdout = wr
	// Concurrent reader: a frame larger than the pipe buffer must not deadlock.
	done := make(chan string, 1)
	go func() {
		var sb strings.Builder
		buf := make([]byte, 4096)
		for {
			n, rerr := rd.Read(buf)
			if n > 0 {
				sb.Write(buf[:n])
			}
			if rerr != nil {
				break
			}
		}
		done <- sb.String()
	}()

	r := NewRenderer(output.ModeHuman).SetCoverageFrom(snap)
	r.PrintAllMock(results, insights, func(string) string { return snap.Hostname })
	for _, ins := range insights {
		if ins.Details != nil {
			r.renderDetails(ins.Details)
		}
	}
	_ = r.PrintSummary(insights, 0)

	_ = wr.Close()
	os.Stdout = oldStdout
	frame := <-done
	_ = rd.Close()
	return frame
}

func FuzzTUIStyledFrameNoHostEscape(f *testing.F) {
	seeds := []string{
		"plain host-01",
		"esc\x1b[31mRED\x1b[0m",                         // CSI SGR colour
		"clr\x1b[2Jwipe",                                // CSI non-m: clear screen
		"osc52\x1b]52;c;ZXZpbA==\x07",                   // OSC 52 clipboard write
		"osc8\x1b]8;;http://evil/\x07click\x1b]8;;\x07", // OSC 8 hyperlink
		"title\x1b]0;pwned\x07",                         // window-title rewrite
		"c1raw\x9bmcsi",                                 // raw C1 CSI byte 0x9B
		"c1enc\xc2\x9bcsi",                              // UTF-8-encoded C1
		"bidi\u202eKO\u202c vs OK",                      // RLO override (reorder; not control)
		"iso\u2066FAIL\u2069",                           // bidi isolate
		"wide世界CJK",                                     // wide runes
		"combine á̂̃e",                                 // combining marks
		"zwj\u200d\u200dzero",                           // zero-width joiners
		"newline\nfake\n### forged CRIT",                // line-forge attempt
		"nul\x00bell\x07bs\x08del\x7f",                  // assorted C0 + DEL
		"bad\xff\xfe\xc0utf8",                           // invalid UTF-8
	}
	for _, s := range seeds {
		f.Add(s)
	}

	f.Fuzz(func(t *testing.T, s string) {
		tu1FrameMu.Lock()
		defer tu1FrameMu.Unlock()

		snap, insights, results := buildHostileFrame(s)
		n := len(s)

		var ascii, truecolor string
		resource.Check(t, n, tu1FrameAllocFactor, func() {
			ascii = renderFrameLocked(t, termenv.Ascii, snap, insights, results)
		})
		// PRIMARY: under Ascii dsd emits no styling ESC, so a clean frame proves
		// the host contributed no terminal control through any styled sink.
		assertFrameClean(t, "ascii-frame", ascii)

		resource.Check(t, n, tu1FrameAllocFactor, func() {
			truecolor = renderFrameLocked(t, termenv.TrueColor, snap, insights, results)
		})
		// SECONDARY: stripping dsd's own CSI-SGR grammar from the styled frame must
		// reproduce the Ascii frame byte-for-byte. If sanitization let a host CSI-SGR
		// through, it would be present in the Ascii frame but removed from the styled
		// frame by sgrRe (indistinguishable from dsd's), so the two would diverge —
		// and the primary oracle already fired on the Ascii frame. If the styled path
		// mangled anything, this also diverges.
		stripped := sgrRe.ReplaceAllString(truecolor, "")
		if stripped != ascii {
			t.Fatalf("styled frame != ascii frame after stripping dsd CSI-SGR (input len %d):\n--- ascii ---\n%q\n--- styled-stripped ---\n%q", n, ascii, stripped)
		}
	})
}
