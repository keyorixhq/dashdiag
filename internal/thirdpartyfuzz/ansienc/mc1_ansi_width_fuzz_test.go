package ansienc

// MC1 target 3 — charmbracelet/x/ansi width / truncate / wrap invariants on
// host-derived text.
//
// Reachability: DashDiag never imports github.com/charmbracelet/x/ansi
// directly, but every styled terminal line it prints goes through
// lipgloss (`render.StyleXxx.Render(hostText)` in internal/render/health.go,
// verdict.go, diff.go, topcatch.go). lipgloss v1.1.0 measures and lays out that
// text with x/ansi — `ansi.StringWidth` for every Render/Width/alignment call,
// and `ansi.Wrap`/`ansi.Truncate` when a Width/MaxWidth is set on the style.
// The strings rendered are host-derived (check names, status messages,
// drill-down titles/values, remediation hints), i.e. attacker-influenceable on
// a compromised or hostile diagnosed host. So the ansi measurement/wrapping
// layer is on a real DashDiag input path.
//
// What is ACTUALLY reached today vs. reported upstream-style:
//   - ansi.StringWidth and ansi.Strip ARE reached: lipgloss calls StringWidth on
//     every Render and uses an ANSI-aware strip when it has to recompute a
//     styled string's visible width. Invariant failures here are REACHABLE.
//   - ansi.Truncate / ansi.Wrap / ansi.Hardwrap are reached by lipgloss ONLY
//     when a style carries an explicit Width()/MaxWidth(); the current render
//     styles set neither, so these are exercised here as a LIBRARY-level
//     (upstream-style) oracle and any finding is labelled "not reachable" until
//     a width-constrained style lands. They are fuzzed now because this program
//     has repeatedly found bugs in small leaf text parsers and the wrap/truncate
//     code is the classic place an escape sequence gets split.
//
// INVARIANTS asserted (see INVARIANTS.d/mc1-thirdparty-ansi.md):
//   W1 width bound   — StringWidth(Truncate(s,w,"")) <= w (valid UTF-8): Truncate
//                      drops content to fit, so its output is never wider than the
//                      limit. (The analogous Hardwrap per-line bound is NOT a
//                      universal property and is reported, not asserted — see the
//                      Hardwrap note and EXPECTED-DIFFERENCE F2.)
//   W2 idempotence   — Truncate(Truncate(s,w,""),w,"") == Truncate(s,w,"") (valid
//                      UTF-8) and Strip(Strip(s)) == Strip(s) (any bytes). Hardwrap
//                      idempotence is NOT asserted (F2).
//   W3 no ESC from host — if the input carries no ESC (0x1b), neither does any
//                      output: the measurement/wrapping layer must not SYNTHESISE
//                      a terminal escape out of plain host text.
//   W4 no new introducer — a truncate/wrap must not INCREASE the number of ESC
//                      (0x1b) bytes: count(result) <= count(input). It cannot
//                      synthesise a new escape introducer or duplicate one when
//                      it splits/rejoins text. (ansi.Strip is deliberately lenient
//                      — it removes even a dangling "\x1b[" at EOF — so the
//                      stronger "Strip leaves no ESC" phrasing is a DEAD oracle for
//                      Truncate/Wrap and is only asserted for Strip itself, where
//                      leaving an ESC WOULD be a real defect.)
//   W5 width stability — StringWidth(Strip(s)) == StringWidth(s): escapes are
//                      zero-width, so stripping them must not change the measured
//                      width.
//   Plus the shared resource oracle: bounded alloc / wall time / no goroutine
//     growth per input.
//
// Does NOT verify: that StringWidth matches any particular terminal's actual
// rendering (grapheme/east-asian width tables are the library's business, not an
// invariant we can independently derive); the Wordwrap breakpoint semantics
// beyond width; styled-color (termenv/colorprofile) output — that path is the
// subject of the render-funnel target (FuzzRenderFunnelNoTerminalInjection),
// which asserts the stronger "no ESC AT ALL in the plain funnels" property; and
// bidi/Trojan-Source reordering (a separate reported gap). It does not assert a
// LOWER bound on Truncate width (a truncation to fewer cells than requested, e.g.
// when a wide grapheme straddles the boundary, is allowed and expected).

import (
	"strings"
	"testing"
	"unicode/utf8"

	"github.com/charmbracelet/x/ansi"

	"github.com/keyorixhq/dashdiag/internal/testutil/resource"
)

// ansi node-tree parsing + grapheme segmentation allocates several buffers per
// call; measured worst case on these string-sized inputs is well under ~256x,
// so factor 512 gives ~2x headroom while still tripping a super-linear blow-up
// or a hang. The functions are string transforms, so alloc is naturally linear
// in input length.
const mc1AnsiAllocFactor = 512

func mc1AnsiSeeds() []string {
	return []string{
		"",
		"plain host-01",
		"a\x1b[31mred\x1b[0mb",                      // SGR colour around text
		"\x1b[31m\x1b[1m\x1b[4mstacked\x1b[0m",      // stacked SGR
		"wide:日本語テキスト",                              // east-asian wide runes
		"emoji:👨‍👩‍👧‍👦 family",                      // ZWJ grapheme cluster
		"combining: é́́acute",                      // combining marks
		"osc\x1b]8;;http://x/\x07link\x1b]8;;\x07",  // OSC 8 hyperlink
		"tab\tand\nnewline",                         // C0 controls
		"truncated-esc\x1b[",                        // dangling CSI introducer in INPUT
		"lone-esc\x1b",                              // bare ESC
		strings.Repeat("x", 300),                    // long ascii
		strings.Repeat("あ", 200),                    // long wide
		strings.Repeat("\x1b[31m", 100) + "payload", // many escapes
		"bad\xff\xfeutf8",                           // invalid UTF-8
		"hyphen-at-the-very-edge-breakpoint-word",   // wrap breakpoint
		"\x1b[38;2;255;0;0mtruecolor\x1b[0m long run",
	}
}

// containsESC reports whether s has a raw ESC (0x1b) byte.
func containsESC(s string) bool { return strings.IndexByte(s, 0x1b) >= 0 }

// escCount counts raw ESC (0x1b) bytes.
func escCount(s string) int { return strings.Count(s, "\x1b") }

func FuzzAnsiWidthTruncateWrap(f *testing.F) {
	for _, s := range mc1AnsiSeeds() {
		f.Add(s, 8)
	}

	f.Fuzz(func(t *testing.T, s string, rawW int) {
		// Bound the width to the range a terminal lays text out in; a negative or
		// absurd width is not a host-reachable terminal column count, and the
		// libraries document limit as a cell count. 0..512 covers narrow panes to
		// a very wide terminal.
		w := rawW % 513
		if w < 0 {
			w = -w
		}
		n := len(s)
		inputHadESC := containsESC(s)

		// ── Truncate ────────────────────────────────────────────────────────
		var trunc string
		resource.Check(t, n, mc1AnsiAllocFactor, func() {
			trunc = ansi.Truncate(s, w, "")
		})
		// W1/W2 for Truncate are grapheme-width properties, so they are scoped to
		// valid UTF-8: on malformed bytes ansi's grapheme segmentation (and the
		// width it derives) is implementation-defined, so neither the width bound
		// nor idempotence is a guaranteed property there — same scoping as W5.
		if utf8.ValidString(s) {
			// W1: never wider than requested.
			if tw := ansi.StringWidth(trunc); tw > w {
				t.Fatalf("W1 Truncate width over limit: input=%q w=%d -> %q width=%d", s, w, trunc, tw)
			}
			// W2: idempotent.
			if again := ansi.Truncate(trunc, w, ""); again != trunc {
				t.Fatalf("W2 Truncate not idempotent: input=%q w=%d\n first=%q\n second=%q", s, w, trunc, again)
			}
		}
		// W3: no ESC synthesised from ESC-free host text.
		if !inputHadESC && containsESC(trunc) {
			t.Fatalf("W3 Truncate introduced an ESC from ESC-free input: %q w=%d -> %q", s, w, trunc)
		}
		// W4: never introduces/duplicates an escape introducer.
		if escCount(trunc) > escCount(s) {
			t.Fatalf("W4 Truncate increased ESC count: input=%q (%d ESC) w=%d -> %q (%d ESC)", s, escCount(s), w, trunc, escCount(trunc))
		}

		// ── Hardwrap (strict per-line width) ────────────────────────────────
		if w >= 1 {
			var hw string
			resource.Check(t, n, mc1AnsiAllocFactor, func() {
				hw = ansi.Hardwrap(s, w, false)
			})
			// W3/W4 are byte-level and hold for any input (incl. invalid UTF-8).
			if !inputHadESC && containsESC(hw) {
				t.Fatalf("W3 Hardwrap introduced an ESC from ESC-free input: %q limit=%d", s, w)
			}
			if escCount(hw) > escCount(s) {
				t.Fatalf("W4 Hardwrap increased ESC count: input=%q (%d ESC) limit=%d -> %q (%d ESC)", s, escCount(s), w, hw, escCount(hw))
			}
			// NOTE: the per-line WIDTH BOUND (W1) and IDEMPOTENCE (W2) are NOT
			// asserted for Hardwrap. Fuzzing established they are not universal
			// properties of ansi.Hardwrap (characterised as EXPECTED-DIFFERENCE F2):
			// Hardwrap refuses to split a grapheme cluster, so a cluster wider than
			// the limit (limit=1 with a width-2 east-asian/emoji char; a U+0601
			// U+0601 '0' prepended-mark cluster of width 3 even at limit=2) is
			// emitted whole on an over-limit line, and re-wrapping is not a fixed
			// point — AND the library is internally inconsistent about whether such
			// a cluster is splittable. None of this is reachable in DashDiag
			// (lipgloss sets no width on host text, and SanitizeControl precedes any
			// ansi path), so it is reported, not asserted. Truncate — which DROPS
			// content to fit rather than refusing to split — keeps a reliable width
			// bound (W1 above) and is the width invariant this target asserts.
		}

		// ── Wrap (word-aware) ───────────────────────────────────────────────
		if w >= 1 {
			var wr string
			resource.Check(t, n, mc1AnsiAllocFactor, func() {
				wr = ansi.Wrap(s, w, "")
			})
			if !inputHadESC && containsESC(wr) {
				t.Fatalf("W3 Wrap introduced an ESC from ESC-free input: %q limit=%d -> %q", s, w, wr)
			}
			if escCount(wr) > escCount(s) {
				t.Fatalf("W4 Wrap increased ESC count: input=%q (%d ESC) limit=%d -> %q (%d ESC)", s, escCount(s), w, wr, escCount(wr))
			}
		}

		// ── Strip + width stability ─────────────────────────────────────────
		var stripped string
		resource.Check(t, n, mc1AnsiAllocFactor, func() {
			stripped = ansi.Strip(s)
		})
		// W4 Strip-removes-all-ESC is scoped to valid UTF-8. On INVALID UTF-8,
		// ansi.Strip can leave a raw ESC behind when the ESC is immediately
		// preceded by an invalid lead byte (fuzzer-minimised: Strip("\xe8\x1b") ==
		// "\xe8\x1b"): the broken lead byte derails the escape-sequence scanner so
		// the following ESC is not recognised as an introducer. That is a real
		// library robustness gap (reported F3, HARDENING/upstream), but it is NOT
		// reachable from DashDiag: every host string reaching a lipgloss/ansi path
		// is first run through output.SanitizeControl, which replaces invalid
		// UTF-8 — so ansi never sees the malformed bytes that trigger it. The
		// assertion is scoped to the guarantee that holds, not weakened to accept
		// a surviving ESC on valid input.
		if utf8.ValidString(s) && containsESC(stripped) {
			t.Fatalf("W4 Strip left an ESC behind on valid UTF-8: input=%q -> %q", s, stripped)
		}
		if again := ansi.Strip(stripped); again != stripped {
			t.Fatalf("W2 Strip not idempotent: input=%q\n first=%q\n second=%q", s, stripped, again)
		}
		// W5: escapes are zero width, so stripping must not change measured width.
		// Only meaningful when the input is valid UTF-8 (StringWidth's grapheme
		// segmentation is defined on valid UTF-8; invalid bytes have
		// implementation-defined width that need not survive a Strip rewrite).
		if utf8.ValidString(s) {
			if ws, wss := ansi.StringWidth(s), ansi.StringWidth(stripped); ws != wss {
				t.Fatalf("W5 StringWidth changed across Strip: input=%q width=%d stripped=%q width=%d", s, ws, stripped, wss)
			}
		}
	})
}
