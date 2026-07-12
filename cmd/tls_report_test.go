//go:build linux || darwin

package cmd

import (
	"strings"
	"testing"
	"time"

	"github.com/keyorixhq/dashdiag/internal/output"
)

// Golden-output tests for tls.go's printCertResult and renderTLSResults.
// IMPORTANT: renderTLSResults calls os.Exit(1)/os.Exit(2) when any WARN/CRIT/
// ERR result is present — that would kill the whole test binary. Only the
// all-OK path (no exit call) is exercised here; printCertResult itself is
// tested directly for the WARN/CRIT/ERR display since it has no exit call.
// No t.Parallel() (corrupts captureStdout's shared os.Stdout swap).

func TestPrintCertResultHealthy(t *testing.T) {
	out := captureStdout(t, func() {
		printCertResult(certResult{Path: "/etc/ssl/cert.pem", Subject: "CN=example.com", Expiry: time.Now().AddDate(0, 1, 0), DaysLeft: 30, Level: "OK"}, output.ModePlain)
	})
	if !strings.Contains(out, "example.com") || !strings.Contains(out, "30 days") {
		t.Errorf("a healthy cert should show its subject and days remaining, got:\n%s", out)
	}
}

func TestPrintCertResultExpired(t *testing.T) {
	out := captureStdout(t, func() {
		printCertResult(certResult{Path: "/etc/ssl/cert.pem", Expiry: time.Now().AddDate(0, 0, -5), DaysLeft: -5, Level: "CRIT"}, output.ModePlain)
	})
	if !strings.Contains(out, "EXPIRED 5 days ago") {
		t.Errorf("an expired cert should show days-since-expiry, not a negative day count, got:\n%s", out)
	}
}

func TestPrintCertResultError(t *testing.T) {
	out := captureStdout(t, func() {
		printCertResult(certResult{Path: "remote.example:443", Level: "ERR", Err: "connection refused", Remote: true}, output.ModePlain)
	})
	if !strings.Contains(out, "connection refused") || !strings.Contains(out, "[remote]") {
		t.Errorf("an unreachable remote cert should show its error and the remote tag, got:\n%s", out)
	}
	if strings.Contains(out, "Subject:") {
		t.Errorf("an errored cert has no subject to show, got:\n%s", out)
	}
}

func TestPrintCertResultSelfSigned(t *testing.T) {
	out := captureStdout(t, func() {
		printCertResult(certResult{Path: "cert.pem", Expiry: time.Now().AddDate(1, 0, 0), DaysLeft: 365, Level: "OK", SelfSigned: true}, output.ModePlain)
	})
	if !strings.Contains(out, "[self-signed]") {
		t.Errorf("a self-signed cert should be tagged, got:\n%s", out)
	}
}

// TestRenderTLSResultsAllHealthy exercises the one path that does NOT call
// os.Exit — every result OK.
func TestRenderTLSResultsAllHealthy(t *testing.T) {
	out := captureStdout(t, func() {
		renderTLSResults([]certResult{
			{Path: "a.pem", Expiry: time.Now().AddDate(0, 6, 0), DaysLeft: 180, Level: "OK"},
		}, true, output.ModePlain)
	})
	if !strings.Contains(out, "All 1 certificate(s) healthy") {
		t.Errorf("all-OK results should summarize as healthy with no exit call, got:\n%s", out)
	}
}

// TestRenderTLSResultsAllHealthy_ShowAllFalse covers the showAll=false branch
// of the all-OK summary (the "use --all" hint) and the showAll=false skip of
// per-cert OK detail lines — still the no-os.Exit path.
func TestRenderTLSResultsAllHealthy_ShowAllFalse(t *testing.T) {
	out := captureStdout(t, func() {
		renderTLSResults([]certResult{
			{Path: "a.pem", Subject: "CN=a.example", Expiry: time.Now().AddDate(0, 6, 0), DaysLeft: 180, Level: "OK"},
		}, false, output.ModePlain)
	})
	if !strings.Contains(out, "All 1 certificate(s) healthy") {
		t.Errorf("all-OK results should summarize as healthy, got:\n%s", out)
	}
	if !strings.Contains(out, "use --all to show individual certs") {
		t.Errorf("showAll=false should hint at --all, got:\n%s", out)
	}
	if strings.Contains(out, "a.example") {
		t.Errorf("showAll=false should skip individual OK cert detail lines, got:\n%s", out)
	}
}
