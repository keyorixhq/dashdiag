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

// TestPrintDNSQualityFlags covers the quality-flag lines that only render when
// their respective condition is set — nameserver count, loopback NS, high
// ndots, IPv6-only, duplicate nameservers, and the public-DNS-fallback note.
func TestPrintDNSQualityFlags(t *testing.T) {
	out := captureStdout(t, func() {
		printDNS(&models.DNSResolverInfo{
			Available: true, Manager: "resolv.conf", ConfigFile: "/etc/resolv.conf.custom",
			StubMode:            true,
			Nameservers:         []string{"1.1.1.1", "8.8.8.8", "9.9.9.9", "4.4.4.4"},
			SearchDomains:       []string{"example.com"},
			Options:             []string{"timeout:2"},
			ExternalResolvesOK:  true,
			ExternalLatencyMs:   12,
			InternalResolvesOK:  false,
			TooManyNameservers:  true,
			HasLoopback:         true,
			NdotsHigh:           5,
			IPv6Only:            true,
			DuplicateNameserver: []string{"1.1.1.1"},
			PublicFallback:      true,
		}, output.ModePlain)
	})
	for _, want := range []string{
		"resolv.conf.custom", "stub", "example.com", "timeout:2",
		"ok  12ms", "could not resolve own hostname",
		"libc silently ignores", "Loopback NS", "high, may cause excessive lookups",
		"IPv6-only", "1.1.1.1", "8.8.8.8/1.1.1.1",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("printDNS quality-flags output missing %q, got:\n%s", want, out)
		}
	}
}

// TestPrintDNSNoNameservers covers the "none configured" WARN branch.
func TestPrintDNSNoNameservers(t *testing.T) {
	out := captureStdout(t, func() {
		printDNS(&models.DNSResolverInfo{Available: true, Manager: "resolv.conf"}, output.ModePlain)
	})
	if !strings.Contains(out, "none configured") {
		t.Errorf("no nameservers should say none configured, got:\n%s", out)
	}
}

// TestPrintDNSExternalFailedWithError covers the FAILED branch's error-detail
// line, which only renders when ResolvTestError is set.
func TestPrintDNSExternalFailedWithError(t *testing.T) {
	out := captureStdout(t, func() {
		printDNS(&models.DNSResolverInfo{
			Available: true, Manager: "resolv.conf",
			ExternalResolvesOK: false, ResolvTestError: "no route to host",
		}, output.ModePlain)
	})
	if !strings.Contains(out, "FAILED") || !strings.Contains(out, "no route to host") {
		t.Errorf("a failed resolution with an error detail should show both, got:\n%s", out)
	}
}
