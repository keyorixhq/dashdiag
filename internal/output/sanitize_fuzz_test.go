package output

import (
	"io"
	"strings"
	"testing"
	"unicode"
	"unicode/utf8"

	"github.com/charmbracelet/lipgloss"
)

// FuzzSanitizeThenRenderNoRawEscape fuzzes the shipped SanitizeControl, then
// renders its output through lipgloss and asserts no raw ESC survives.
//
// Lineage: this target began as harness #50 in the external fuzz-corpus repo,
// which tested a hand-kept mirror of SanitizeControl rather than this
// function. The mirror handled invalid UTF-8 and the shipped code did not, so
// the harness was green for code DashDiag did not ship. It now lives in-tree
// and calls the real function so the two cannot drift.
//
// Properties: no unicode.IsControl rune and no invalid UTF-8 in the output
// (so no raw 0x80-0x9F byte), no ESC after rendering, and idempotence.
func FuzzSanitizeThenRenderNoRawEscape(f *testing.F) {
	f.Add("esc\x1b[31mred")
	f.Add("osc\x1b]0;title\x07")
	f.Add("c1raw\x9bcsi")
	f.Add("c1enc\xc2\x9bcsi")
	f.Add("bad\xff\xfe")
	f.Fuzz(func(t *testing.T, s string) {
		out := SanitizeControl(s)

		if strings.ContainsFunc(out, unicode.IsControl) {
			t.Fatalf("SanitizeControl output still has a control rune (input len %d)", len(s))
		}
		if !utf8.ValidString(out) {
			t.Fatalf("SanitizeControl output is not valid UTF-8 (input len %d)", len(s))
		}
		if again := SanitizeControl(out); again != out {
			t.Fatalf("SanitizeControl not idempotent (input len %d)", len(s))
		}

		r := lipgloss.NewRenderer(io.Discard)
		rendered := r.NewStyle().Width(20).Align(lipgloss.Left).Render(out)
		if strings.ContainsRune(rendered, 0x1b) {
			t.Fatalf("render emitted ESC after sanitize (input len %d)", len(s))
		}
	})
}
