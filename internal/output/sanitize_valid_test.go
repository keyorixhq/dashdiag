package output

import (
	"strings"
	"testing"
)

// Valid, control-free UTF-8 must come back byte-identical.
func TestSanitizeControlValidUTF8Identity(t *testing.T) {
	t.Parallel()
	tests := []struct{ name, in string }{
		{"ASCII", "nginx: worker process (pid 42) [OK]"},
		{"accents", "café naïve Übergrößenträger señor"},
		{"CJK", "日本語のテキスト 中文 한국어"},
		{"emoji", "ok \U0001F600 \U0001F3FB \u2764\uFE0F \U0001F468\u200d\U0001F469\u200d\U0001F467"},
		{"U+FFFD already present", "already � replaced"},
		{"empty", ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := SanitizeControl(tt.in); got != tt.in {
				t.Errorf("SanitizeControl(%q) = %q, want unchanged", tt.in, got)
			}
		})
	}
}

func BenchmarkSanitizeControl1MB(b *testing.B) {
	s := strings.Repeat("café 日本語 nginx worker \U0001F600 ", 40000)[:1<<20]
	s = strings.ToValidUTF8(s, "")
	b.SetBytes(int64(len(s)))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = SanitizeControl(s)
	}
}
