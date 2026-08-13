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

// TestPrintCertResult_StripsControlChars guards terminal escape injection:
// the Subject CN is attacker-controlled — whoever generated the certificate
// (or a MITM presenting one) chooses this string — and must not carry raw
// control bytes into the terminal.
func TestPrintCertResult_StripsControlChars(t *testing.T) {
	out := captureStdout(t, func() {
		printCertResult(certResult{
			Path: "/etc/ssl/cert.pem", Subject: "CN=evil\x1b]0;pwned\x07",
			Expiry: time.Now().AddDate(0, 1, 0), DaysLeft: 30, Level: "OK",
		}, output.ModePlain)
	})
	if strings.Contains(out, "\x1b") {
		t.Errorf("printCertResult output still contains ESC byte:\n%s", out)
	}
	if !strings.Contains(out, "CN=evil]0;pwned") {
		t.Errorf("printCertResult output missing sanitized subject:\n%s", out)
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

// TestRenderTLSResultsAllHealthy_MultipleSorted exercises renderTLSResults'
// real sort.Slice call (not just the standalone comparator test) with
// multiple same-severity results, confirming soonest-expiry-first ordering
// end to end on the one path that never calls os.Exit.
func TestRenderTLSResultsAllHealthy_MultipleSorted(t *testing.T) {
	out := captureStdout(t, func() {
		renderTLSResults([]certResult{
			{Path: "later.pem", Subject: "CN=later", Expiry: time.Now().AddDate(1, 0, 0), DaysLeft: 365, Level: "OK"},
			{Path: "sooner.pem", Subject: "CN=sooner", Expiry: time.Now().AddDate(0, 1, 0), DaysLeft: 30, Level: "OK"},
		}, true, output.ModePlain)
	})
	soonerIdx := strings.Index(out, "sooner.pem")
	laterIdx := strings.Index(out, "later.pem")
	if soonerIdx == -1 || laterIdx == -1 || soonerIdx > laterIdx {
		t.Errorf("soonest-expiring cert should print first, got:\n%s", out)
	}
}

// TestCertResultLess covers both branches of the sort comparator pulled out
// of renderTLSResults: differing severity (CRIT sorts before OK) and same
// severity, differing expiry (soonest-expiring sorts first). Kept as a
// standalone pure-function test since exercising both branches through
// renderTLSResults itself would require a non-OK result, which triggers that
// function's os.Exit calls.
func TestCertResultLess(t *testing.T) {
	t.Parallel()
	crit := certResult{Level: "CRIT", DaysLeft: 100}
	ok := certResult{Level: "OK", DaysLeft: 1}
	if !certResultLess(crit, ok) {
		t.Errorf("CRIT should sort before OK regardless of DaysLeft")
	}
	if certResultLess(ok, crit) {
		t.Errorf("OK should not sort before CRIT")
	}

	soon := certResult{Level: "OK", DaysLeft: 5}
	later := certResult{Level: "OK", DaysLeft: 30}
	if !certResultLess(soon, later) {
		t.Errorf("same-severity results should sort by soonest expiry first")
	}
	if certResultLess(later, soon) {
		t.Errorf("later-expiring result should not sort before sooner one")
	}
}

// TestCountTLSLevels covers the level-tally logic pulled out of
// renderTLSResults, including all four Level branches (CRIT/WARN/OK/ERR) in
// one pass — something renderTLSResults itself can never safely exercise
// together since any non-OK result triggers its os.Exit calls.
func TestCountTLSLevels(t *testing.T) {
	t.Parallel()
	crits, warns, oks, errs := countTLSLevels([]certResult{
		{Level: "CRIT"}, {Level: "CRIT"},
		{Level: "WARN"},
		{Level: "OK"}, {Level: "OK"}, {Level: "OK"},
		{Level: "ERR"},
	})
	if crits != 2 || warns != 1 || oks != 3 || errs != 1 {
		t.Errorf("countTLSLevels = (%d,%d,%d,%d), want (2,1,3,1)", crits, warns, oks, errs)
	}

	crits, warns, oks, errs = countTLSLevels(nil)
	if crits != 0 || warns != 0 || oks != 0 || errs != 0 {
		t.Errorf("countTLSLevels(nil) = (%d,%d,%d,%d), want all zero", crits, warns, oks, errs)
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
