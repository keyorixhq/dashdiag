package output

import "testing"

// DL1 §3 finding #1 / DH1: SanitizeControl must also strip the Unicode
// bidirectional formatting runes (category Cf, which unicode.IsControl misses) —
// the Trojan-Source / CVE-2021-42574 visual-reordering class — while leaving the
// legitimate ZERO WIDTH JOINER (U+200D) and variation selectors emoji use
// untouched. Inputs are built with string(rune(...)) so no bidi rune is embedded
// literally in this source file.
func TestSanitizeControlStripsBidi(t *testing.T) {
	t.Parallel()
	const (
		LRE = rune(0x202A)
		RLE = rune(0x202B)
		PDF = rune(0x202C)
		LRO = rune(0x202D)
		RLO = rune(0x202E)
		LRI = rune(0x2066)
		RLI = rune(0x2067)
		FSI = rune(0x2068)
		PDI = rune(0x2069)
		LRM = rune(0x200E)
		RLM = rune(0x200F)
		ALM = rune(0x061C)
		ZWJ = rune(0x200D) // legitimate (emoji) — must survive
	)
	tests := []struct {
		name string
		in   string
		want string
	}{
		{"strips RLO override", "KO" + string(RLO), "KO"},
		{"strips LRO override", string(LRO) + "flip", "flip"},
		{"strips LRE/PDF embedding pair", string(LRE) + "x" + string(PDF), "x"},
		{"strips RLE", "a" + string(RLE) + "b", "ab"},
		{"strips isolate runes LRI/RLI/FSI/PDI",
			string(LRI) + "a" + string(RLI) + "b" + string(FSI) + "c" + string(PDI), "abc"},
		{"strips implicit marks LRM/RLM/ALM",
			"a" + string(LRM) + "b" + string(RLM) + "c" + string(ALM) + "d", "abcd"},
		{"RLO combined with ESC strips both", "x" + string(RLO) + "\x1b[31m", "x[31m"},
		{"ZWJ survives (legitimate emoji joiner)",
			"a" + string(ZWJ) + "b", "a" + string(ZWJ) + "b"},
		{"plain text with no bidi is unchanged", "nginx worker 42", "nginx worker 42"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := SanitizeControl(tt.in); got != tt.want {
				t.Errorf("SanitizeControl(%q) = %q, want %q", tt.in, got, tt.want)
			}
		})
	}
}

func TestSanitizeControl(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name string
		in   string
		want string
	}{
		{"plain ASCII passes through", "nginx", "nginx"},
		{"empty string", "", ""},
		{"UTF-8 passes through", "café 日本語", "café 日本語"},
		{"strips ESC (ANSI escape start)", "evil\x1b[31mred\x1b[0m", "evil[31mred[0m"},
		{"strips OSC title-rewrite sequence", "\x1b]0;pwned\x07innocent", "]0;pwnedinnocent"},
		{"strips bell", "beep\x07", "beep"},
		{"strips carriage return (overwrite-line trick)", "real line\rFAKE OK\r", "real lineFAKE OK"},
		{"strips backspace", "abc\x08\x08\x08XYZ", "abcXYZ"},
		{"strips NUL", "trunc\x00ated", "truncated"},
		{"strips C1 control (NEL, U+0085)", "before\u0085after", "beforeafter"},
		{"tab and newline are also control runes and get stripped", "a\tb\nc", "abc"},
		{"raw C1 byte (invalid UTF-8) becomes U+FFFD", "raw\x9braw", "raw�raw"},
		{"invalid bytes become U+FFFD", "mixed\xffbytes\xfe", "mixed�bytes�"},
		{"invalid byte plus control rune", "a\xffb\x1bc", "a�bc"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := SanitizeControl(tt.in); got != tt.want {
				t.Errorf("SanitizeControl(%q) = %q, want %q", tt.in, got, tt.want)
			}
		})
	}
}
