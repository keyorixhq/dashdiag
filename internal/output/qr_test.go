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
