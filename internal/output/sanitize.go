package output

import (
	"strings"
	"unicode"
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
// Printable text, including multi-byte UTF-8, passes through unchanged;
// only unicode.IsControl runes are removed (not replaced), so the output
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
