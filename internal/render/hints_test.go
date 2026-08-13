package render

import (
	"io"
	"os"
	"strings"
	"testing"

	"github.com/keyorixhq/dashdiag/internal/models"
	"github.com/keyorixhq/dashdiag/internal/output"
)

// captureStdout redirects os.Stdout for the duration of fn and returns what was
// written. printHints/printHintsPlain write directly to os.Stdout, so this is
// the only way to observe their grouping behavior. Output is small (well under
// the pipe buffer), so writing fully before reading does not deadlock.
func captureStdout(t *testing.T, fn func()) string {
	t.Helper()
	old := os.Stdout
	rd, wr, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	os.Stdout = wr
	fn()
	_ = wr.Close()
	os.Stdout = old
	data, _ := io.ReadAll(rd)
	_ = rd.Close()
	return string(data)
}

// Hints sharing a label ("to fix:", "to inspect:", "to persist:") are grouped
// under a single header; commands with no known prefix print as-is.
var hintInput = []string{
	"to fix: chmod 600 /etc/ssh/sshd_config",
	"to fix: systemctl restart sshd",
	"to inspect: journalctl -u sshd",
	"a raw line with no prefix",
}

func TestPrintHintsPlainGroups(t *testing.T) {
	r := NewRenderer(output.ModePlain)
	out := captureStdout(t, func() { r.printHintsPlain(hintInput) })

	for _, want := range []string{
		"chmod 600 /etc/ssh/sshd_config",
		"systemctl restart sshd",
		"to inspect: journalctl -u sshd",
		"a raw line with no prefix",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("plain hints missing %q\n---\n%s", want, out)
		}
	}
	// The two "to fix" commands must be grouped under ONE header — the label text
	// appears exactly once (the commands themselves don't contain it).
	if n := strings.Count(out, "to fix"); n != 1 {
		t.Errorf("expected one 'to fix' group header, found %d\n---\n%s", n, out)
	}
}

func TestPrintHintsStyledGroups(t *testing.T) {
	r := NewRenderer(output.ModeHuman)
	out := captureStdout(t, func() { r.printHints(hintInput) })

	// Styling may wrap text in ANSI, but the literal command bytes stay contiguous.
	for _, want := range []string{
		"chmod 600 /etc/ssh/sshd_config",
		"systemctl restart sshd",
		"journalctl -u sshd",
		"a raw line with no prefix",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("styled hints missing %q\n---\n%s", want, out)
		}
	}
	if n := strings.Count(out, "to fix"); n != 1 {
		t.Errorf("expected one 'to fix' group header, found %d\n---\n%s", n, out)
	}
}

// TestPrintHints_StripsControlChars guards terminal escape injection: a hint
// can splice in attacker-influenced text (e.g. a SUID binary path or a
// bootname read from the system), and printHints/printHintsPlain must not
// pass raw control bytes (ESC starts ANSI/OSC escape sequences) straight to
// the terminal.
func TestPrintHints_StripsControlChars(t *testing.T) {
	evil := []string{"to fix: chmod 4755 /tmp/evil\x1b]0;pwned\x07binary"}

	plainOut := captureStdout(t, func() {
		NewRenderer(output.ModePlain).printHintsPlain(evil)
	})
	if strings.Contains(plainOut, "\x1b") {
		t.Errorf("printHintsPlain output still contains ESC byte: %q", plainOut)
	}
	if !strings.Contains(plainOut, "/tmp/evil]0;pwnedbinary") {
		t.Errorf("printHintsPlain output missing sanitized text: %q", plainOut)
	}

	styledOut := captureStdout(t, func() {
		NewRenderer(output.ModeHuman).printHints(evil)
	})
	if strings.Contains(styledOut, "\x1b]0;") {
		t.Errorf("printHints output still contains the injected OSC sequence: %q", styledOut)
	}
}

// TestPrintInsightGroup_StripsControlChars guards terminal escape injection
// on the Check/Message fields — assembled upstream in analysis from
// attacker-influenced data (comm names, cron/log content, cert fields, ...)
// — which must not carry raw control bytes into the terminal.
func TestPrintInsightGroup_StripsControlChars(t *testing.T) {
	evil := []models.Insight{{
		Level:   "CRIT",
		Check:   "Security",
		Message: "suspicious binary \x1b]0;pwned\x07 detected",
	}}

	plainOut := captureStdout(t, func() {
		NewRenderer(output.ModePlain).printInsightGroup(evil)
	})
	if strings.Contains(plainOut, "\x1b") {
		t.Errorf("printInsightGroup (plain) output still contains ESC byte: %q", plainOut)
	}
	if !strings.Contains(plainOut, "suspicious binary ]0;pwned detected") {
		t.Errorf("printInsightGroup (plain) output missing sanitized message: %q", plainOut)
	}

	styledOut := captureStdout(t, func() {
		NewRenderer(output.ModeHuman).printInsightGroup(evil)
	})
	if strings.Contains(styledOut, "\x1b]0;") {
		t.Errorf("printInsightGroup (styled) output still contains the injected OSC sequence: %q", styledOut)
	}
}

func TestPrintHintsEmpty(t *testing.T) {
	r := NewRenderer(output.ModeHuman)
	if out := captureStdout(t, func() { r.printHints(nil) }); out != "" {
		t.Errorf("empty hints should print nothing, got %q", out)
	}
	if out := captureStdout(t, func() { r.printHintsPlain(nil) }); out != "" {
		t.Errorf("empty plain hints should print nothing, got %q", out)
	}
}
