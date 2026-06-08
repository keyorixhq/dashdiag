package cmd

import (
	"strings"

	"github.com/keyorixhq/dashdiag/internal/output"
)

// asciiOr returns an ASCII status token in machine-readable modes (--plain and
// the JSON/YAML formats) and the supplied emoji in human/report modes.
//
// The single-purpose subcommands historically hardcoded emoji in their icon
// helpers regardless of mode, which leaked multibyte glyphs into `--plain`
// output that ASCII parsers and log shippers choke on. Routing every status
// glyph through this helper keeps human output byte-for-byte identical (the
// caller passes the exact emoji, including any alignment spacing) while making
// --plain emit OK/WARN/CRIT/INFO/... tokens.
//
// level is one of the output.StatusIcon keys: "ok", "warn", "fail", "info",
// "pending" — plus the extras handled below ("skip", "off", "unknown").
func asciiOr(level, emoji string, mode output.OutputMode) string {
	if mode == output.ModeHuman || mode == output.ModeReport {
		return emoji
	}
	var token string
	switch level {
	case "skip":
		token = "SKIP"
	case "off":
		token = "OFF"
	case "unknown":
		token = "-"
	default:
		token = output.StatusIcon(level, mode)
	}
	// Carry over the emoji's trailing spaces so callers that relied on the
	// glyph's built-in spacing as a separator (e.g. "%s%d") still get one in
	// machine modes — otherwise "⚠️  3" would collapse to "WARN3".
	return token + emoji[len(strings.TrimRight(emoji, " ")):]
}
