package cmd

import (
	"io"
	"os"
	"strings"
	"testing"

	"github.com/keyorixhq/dashdiag/internal/models"
	"github.com/keyorixhq/dashdiag/internal/output"
)

// captureStdout runs f with os.Stdout redirected to a pipe and returns what was
// written.
func captureStdout(t *testing.T, f func()) string {
	t.Helper()
	old := os.Stdout
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	os.Stdout = w
	done := make(chan string, 1)
	go func() {
		b, _ := io.ReadAll(r)
		done <- string(b)
	}()
	f()
	_ = w.Close()
	os.Stdout = old
	return <-done
}

// When the resolver audit didn't run (non-Linux: Available=false), printDNS must
// report "not available" rather than the zero-value cascade ("External
// resolution FAILED", "none configured") which reads as real failures.
func TestPrintDNSUnavailable(t *testing.T) {
	out := captureStdout(t, func() {
		printDNS(&models.DNSResolverInfo{Available: false}, output.ModePlain)
	})
	if !strings.Contains(out, "not available") {
		t.Errorf("unavailable audit should say 'not available', got: %q", out)
	}
	if strings.Contains(out, "FAILED") {
		t.Errorf("unavailable audit must not print 'External resolution FAILED', got: %q", out)
	}
}

// On Linux (Available=true) a genuine resolution failure must still surface.
func TestPrintDNSAvailableStillReportsFailure(t *testing.T) {
	out := captureStdout(t, func() {
		printDNS(&models.DNSResolverInfo{
			Available:          true,
			Manager:            "systemd-resolved",
			ExternalResolvesOK: false,
		}, output.ModePlain)
	})
	if !strings.Contains(out, "FAILED") {
		t.Errorf("available audit with failing resolution should print FAILED, got: %q", out)
	}
	if strings.Contains(out, "not available") {
		t.Errorf("available audit must not claim 'not available', got: %q", out)
	}
}
