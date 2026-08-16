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
// Printable text, including multi-byte UTF-8, passes through unchanged;
// only unicode.IsControl runes are removed (not replaced), so the value
// stays readable rather than growing placeholder characters.
func SanitizeControl(s string) string {
	if !strings.ContainsFunc(s, unicode.IsControl) {
		return s
	}
	return strings.Map(func(r rune) rune {
		if unicode.IsControl(r) {
			return -1
		}
		return r
	}, s)
}
