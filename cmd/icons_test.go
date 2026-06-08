package cmd

import (
	"testing"

	"github.com/keyorixhq/dashdiag/internal/output"
)

// isASCII reports whether every byte in s is < 0x80 (no multibyte runes).
func isASCII(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] >= 0x80 {
			return false
		}
	}
	return true
}

// asciiOr and netMark are the chokepoints every status glyph in the
// single-purpose subcommands routes through. This locks the real --plain
// contract deterministically at the source — far more durable than grepping
// state-gated command output: --plain status tokens MUST be pure ASCII so log
// shippers and OK/WARN/CRIT parsers don't choke, while human mode keeps the
// glyph. (See the #116 net-banner leak: a hardcoded emoji that bypassed netMark.)
func TestAsciiOrPlainIsASCII(t *testing.T) {
	// Representative emoji per level — the exact glyph callers pass in.
	cases := map[string]string{
		"ok": "✅", "warn": "⚠️ ", "fail": "❌", "info": "ℹ️ ",
		"pending": "⏳", "skip": "⏭️", "off": "⏹", "unknown": "🟡",
	}
	for level, emoji := range cases {
		// --plain must be ASCII.
		if got := asciiOr(level, emoji, output.ModePlain); !isASCII(got) {
			t.Errorf("asciiOr(%q, …, ModePlain) = %q, want pure ASCII", level, got)
		}
		// Human mode keeps the exact glyph (output stays byte-identical).
		if got := asciiOr(level, emoji, output.ModeHuman); got != emoji {
			t.Errorf("asciiOr(%q, %q, ModeHuman) = %q, want the glyph unchanged", level, emoji, got)
		}
	}
}

func TestNetMarkPlainIsASCII(t *testing.T) {
	for _, level := range []string{"ok", "warn", "fail", "info"} {
		plain := netMark(level, output.ModePlain)
		if !isASCII(plain) || plain == "" {
			t.Errorf("netMark(%q, ModePlain) = %q, want a non-empty ASCII token", level, plain)
		}
		// Human mode must NOT be ASCII — it carries the emoji glyph.
		if human := netMark(level, output.ModeHuman); isASCII(human) {
			t.Errorf("netMark(%q, ModeHuman) = %q, want the emoji glyph", level, human)
		}
	}
}
