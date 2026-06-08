package cmd

import (
	"testing"
	"unicode/utf8"
)

func TestTruncateRuneSafe(t *testing.T) {
	// ASCII: unchanged behaviour.
	if got := truncateStr("hello world", 8); got != "hello w…" {
		t.Errorf("truncateStr ASCII = %q, want %q", got, "hello w…")
	}
	if got := truncate("hello world", 8); got != "hello wo…" {
		t.Errorf("truncate ASCII = %q, want %q", got, "hello wo…")
	}
	// Short strings pass through untouched.
	if got := truncateStr("short", 10); got != "short" {
		t.Errorf("truncateStr passthrough = %q", got)
	}

	// Multibyte: the result must stay valid UTF-8 — byte-slicing would split the
	// accented/CJK rune at the boundary into an invalid sequence.
	for _, in := range []string{"aébcdef", "日本語テスト", "café ☃ déjà vu"} {
		for _, fn := range []struct {
			name string
			f    func(string, int) string
		}{{"truncateStr", truncateStr}, {"truncate", truncate}} {
			out := fn.f(in, 4)
			if !utf8.ValidString(out) {
				t.Errorf("%s(%q, 4) = %q is not valid UTF-8", fn.name, in, out)
			}
		}
	}
}
