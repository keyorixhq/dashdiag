package output

import (
	"strings"
	"unicode"
	"unicode/utf8"
)

// SanitizeControl strips ASCII and C1 control characters — including ESC
// (0x1B), which starts ANSI/OSC/DCS escape sequences — from s before it
// reaches a terminal. dsd prints a wide range of attacker-influenced text
// verbatim: process/comm names from /proc, cron and journal log lines,
// certificate fields, subprocess output, and anything replayed from a
// capture bundle. None of that is trustworthy input, and a crafted string
// containing raw control bytes can rewrite the terminal title, hide or
// overwrite already-printed text, or (on vulnerable terminal emulators)
// worse via OSC 52 clipboard writes or DECRQSS-style tricks.
//
// It also strips the Unicode bidirectional formatting runes (U+202A–202E and
// U+2066–2069, plus the implicit directional marks U+200E/U+200F and U+061C):
// these are Unicode category Cf, NOT Cc, so unicode.IsControl does not catch
// them, yet none legitimately appears in the host-derived text dsd prints
// (hostnames, process/comm names, journal lines, certificate fields). A crafted
// string carrying a right-to-left override (U+202E) visually reorders a line in
// a pasted markdown/share/post-mortem report — e.g. making a FAIL read OK to a
// human — the Trojan-Source / CVE-2021-42574 class. The ZERO WIDTH JOINER
// (U+200D) and variation selectors legitimate emoji use are intentionally NOT in
// this set; only the direction-affecting runes are.
//
// Printable text, including multi-byte UTF-8, passes through unchanged; unsafe
// runes are removed (not replaced), so the output stays readable rather than
// growing placeholder characters. Invalid UTF-8 (which includes a raw 8-bit C1
// byte such as 0x9B) is replaced with U+FFFD, so the result is always valid
// UTF-8 and never carries a raw C1 byte.
func SanitizeControl(s string) string {
	if utf8.ValidString(s) && !strings.ContainsFunc(s, unsafeForTerminal) {
		return s
	}
	return strings.Map(func(r rune) rune {
		if unsafeForTerminal(r) {
			return -1
		}
		return r
	}, s)
}

// unsafeForTerminal reports whether r must be stripped before host-derived text
// reaches a terminal or a pasted report: any ASCII/C1 control rune (ESC, the CSI/
// OSC introducers, NUL, CR, …) or a bidi formatting rune (see isBidiFormatting).
func unsafeForTerminal(r rune) bool {
	return unicode.IsControl(r) || isBidiFormatting(r)
}

// isBidiFormatting reports whether r is a Unicode bidirectional formatting rune
// that can visually reorder surrounding text (Trojan-Source / CVE-2021-42574):
// the explicit override/embedding/isolate runes U+202A–202E and U+2066–2069, and
// the implicit directional marks U+200E/U+200F (LRM/RLM) and U+061C (ALM).
func isBidiFormatting(r rune) bool {
	switch r {
	case 0x202A, 0x202B, 0x202C, 0x202D, 0x202E, // LRE RLE PDF LRO RLO
		0x2066, 0x2067, 0x2068, 0x2069, // LRI RLI FSI PDI
		0x200E, 0x200F, // LRM RLM
		0x061C: // ALM
		return true
	}
	return false
}
