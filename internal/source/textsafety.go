package source

import (
	"strings"
	"unicode"
)

// SanitizeControl strips ASCII and C1 control characters — including ESC
// (0x1B), which starts ANSI/OSC/DCS terminal escape sequences — from s.
//
// This mirrors internal/output.SanitizeControl, the render-layer choke point
// dsd normally relies on to protect terminal output. It is duplicated here,
// rather than imported, because internal/collectors is not permitted to
// import internal/output (collectors/ -> models, platform, source ONLY, per
// the layering table in CLAUDE.md — output-> is a render-layer package and
// importing it from collectors would violate the one-way pipeline). This
// package (internal/source) is already a dependency-free leaf that
// internal/collectors imports freely for exec/read hardening, so it is the
// legal home for a second, small copy of the same logic — see
// internal/inventory's own stripControl for identical prior art and
// reasoning.
//
// Some collector-layer fields (subprocess/HTTP-response strings from
// external tools and services: drive model strings, service version
// strings, sysfs sensor labels) are stored directly into model structs and
// never flow through Insight.Message/Insight.Hints or any other
// render-layer choke point today — for those fields, sanitizing here, at
// the point of assignment in the collector, is the only thing that actually
// protects a future renderer from printing raw control bytes.
//
// Like its output-layer mirror it also strips the Unicode bidirectional
// formatting runes (U+202A–202E, U+2066–2069, U+200E/U+200F, U+061C): these are
// category Cf, not Cc, so unicode.IsControl misses them, yet a right-to-left
// override smuggled through a drive-model string or sensor label would visually
// reorder a later report line (Trojan-Source / CVE-2021-42574). Kept identical
// to internal/output.SanitizeControl's rune set so the two cannot drift.
//
// Printable text, including multi-byte UTF-8, passes through unchanged; only the
// unsafe runes are removed (not replaced), so the value stays readable rather
// than growing placeholder characters.
func SanitizeControl(s string) string {
	if !strings.ContainsFunc(s, unsafeForTerminal) {
		return s
	}
	return strings.Map(func(r rune) rune {
		if unsafeForTerminal(r) {
			return -1
		}
		return r
	}, s)
}

// unsafeForTerminal mirrors internal/output.unsafeForTerminal: a control rune
// (unicode.IsControl, incl. ESC and the C1 introducers) or a bidi formatting
// rune (isBidiFormatting).
func unsafeForTerminal(r rune) bool {
	return unicode.IsControl(r) || isBidiFormatting(r)
}

// isBidiFormatting mirrors internal/output.isBidiFormatting: the Unicode
// bidirectional override/embedding/isolate runes and the implicit directional
// marks, which visually reorder surrounding text (Trojan-Source / CVE-2021-42574).
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
