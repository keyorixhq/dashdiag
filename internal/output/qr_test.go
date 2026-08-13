package output

import (
	"io"
	"os"
	"strings"
	"testing"
)

// captureStdout redirects os.Stdout for the duration of fn and returns what
// was written. PrintQRCode writes directly to os.Stdout.
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

func TestPrintQRCode_EmptyURL(t *testing.T) {
	out := captureStdout(t, func() {
		if err := PrintQRCode("", ModeHuman); err != nil {
			t.Errorf("expected nil error, got %v", err)
		}
	})
	if out != "" {
		t.Errorf("expected no output for empty url, got: %s", out)
	}
}

func TestPrintQRCode_PlainMode(t *testing.T) {
	withTTY(t, true, func() {
		out := captureStdout(t, func() {
			if err := PrintQRCode("https://example.com", ModePlain); err != nil {
				t.Errorf("expected nil error, got %v", err)
			}
		})
		if !strings.Contains(out, "Scan or visit: https://example.com") {
			t.Errorf("expected fallback text in plain mode, got: %s", out)
		}
	})
}

func TestPrintQRCode_NoTTYFallsBackRegardlessOfMode(t *testing.T) {
	withTTY(t, false, func() {
		out := captureStdout(t, func() {
			if err := PrintQRCode("https://example.com", ModeHuman); err != nil {
				t.Errorf("expected nil error, got %v", err)
			}
		})
		if !strings.Contains(out, "Scan or visit: https://example.com") {
			t.Errorf("expected fallback text without a TTY, got: %s", out)
		}
	})
}

func TestPrintQRCode_TTYHumanModeRendersQR(t *testing.T) {
	withTTY(t, true, func() {
		out := captureStdout(t, func() {
			if err := PrintQRCode("https://example.com", ModeHuman); err != nil {
				t.Errorf("expected nil error, got %v", err)
			}
		})
		if strings.Contains(out, "Scan or visit:") {
			t.Errorf("expected rendered QR code, not fallback text, got: %s", out)
		}
		if !strings.Contains(out, "https://example.com") {
			t.Errorf("expected URL printed after QR code, got: %s", out)
		}
	})
}

// TestPrintQRCode_JSONYAMLModeIsNoOp guards Finding internal-output-01-01's
// second half: stdout must stay a pure structured-output stream in --json/
// --yaml mode even when stdout happens to be a TTY (an operator running
// `dsd health --json --share` interactively) — PrintQRCode must not write
// anything at all in these modes.
func TestPrintQRCode_JSONYAMLModeIsNoOp(t *testing.T) {
	for _, mode := range []OutputMode{ModeJSON, ModeYAML} {
		withTTY(t, true, func() {
			out := captureStdout(t, func() {
				if err := PrintQRCode("https://example.com", mode); err != nil {
					t.Errorf("expected nil error, got %v", err)
				}
			})
			if out != "" {
				t.Errorf("mode %v: expected no output, got: %q", mode, out)
			}
		})
	}
}

// TestPrintQRCode_SanitizesControlChars guards Finding internal-output-01-01:
// url is written verbatim to stdout with no escape-sequence sanitization in
// all three of PrintQRCode's fallback/QR-render paths. Once --share is wired
// to a real share-link URL, a malicious/MITM'd share server could embed
// ANSI/OSC terminal escape sequences in it.
func TestPrintQRCode_SanitizesControlChars(t *testing.T) {
	evil := "https://example.com/\x1b[2Jevil"
	t.Run("plain mode fallback", func(t *testing.T) {
		withTTY(t, true, func() {
			out := captureStdout(t, func() { _ = PrintQRCode(evil, ModePlain) })
			if strings.ContainsRune(out, 0x1b) {
				t.Errorf("plain mode: control byte survived: %q", out)
			}
		})
	})
	t.Run("no-TTY fallback", func(t *testing.T) {
		withTTY(t, false, func() {
			out := captureStdout(t, func() { _ = PrintQRCode(evil, ModeHuman) })
			if strings.ContainsRune(out, 0x1b) {
				t.Errorf("no-TTY fallback: control byte survived: %q", out)
			}
		})
	})
	t.Run("TTY human mode after QR render", func(t *testing.T) {
		withTTY(t, true, func() {
			out := captureStdout(t, func() { _ = PrintQRCode(evil, ModeHuman) })
			if strings.ContainsRune(out, 0x1b) {
				t.Errorf("TTY human mode: control byte survived: %q", out)
			}
		})
	})
}

func TestPrintQRCode_ContentTooLongFallsBack(t *testing.T) {
	withTTY(t, true, func() {
		longURL := "https://example.com/" + strings.Repeat("a", 5000)
		out := captureStdout(t, func() {
			if err := PrintQRCode(longURL, ModeHuman); err != nil {
				t.Errorf("expected nil error even on encode failure, got %v", err)
			}
		})
		if !strings.Contains(out, "QR: "+longURL) {
			t.Errorf("expected QR-encode-failure fallback, got: %s", out)
		}
	})
}
