package output

import "testing"

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
		{"strips C1 control (NEL, U+0085)", "beforeafter", "beforeafter"},
		{"tab and newline are also control runes and get stripped", "a\tb\nc", "abc"},
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
