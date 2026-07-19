package cmd

import (
	"strings"
	"testing"

	"github.com/keyorixhq/dashdiag/internal/cis"
	"github.com/keyorixhq/dashdiag/internal/models"
	"github.com/keyorixhq/dashdiag/internal/output"
)

// Golden-output tests for cis.go's printCISReport (cisIcon already had
// coverage from an earlier round). No t.Parallel() (corrupts captureStdout's
// shared os.Stdout swap).

func TestPrintCISReportSections(t *testing.T) {
	report := models.CISReport{
		Profile: "CIS Ubuntu 22.04 LTS Level 1", Hostname: "web01",
		Results: []models.CISResult{
			{ID: "5.2.1", Section: "SSH", Description: "Ensure SSH root login disabled", Status: models.CISPass},
			{ID: "5.2.2", Section: "SSH", Description: "Ensure password auth disabled", Status: models.CISFail,
				Finding: "PasswordAuthentication yes", Remediation: "set PasswordAuthentication no"},
			{ID: "6.1.1", Section: "Files", Description: "Ensure permissions on /etc/passwd", Status: models.CISManual,
				Finding: "manual review required"},
		},
		Pass: 1, Fail: 1, Manual: 1,
	}
	out := captureStdout(t, func() { printCISReport(report, false, false, output.ModePlain) })
	if !strings.Contains(out, "web01") {
		t.Errorf("the hostname should be shown, got:\n%s", out)
	}
	if !strings.Contains(out, "SSH") || !strings.Contains(out, "FILES") {
		t.Errorf("section headers should be rendered (uppercased), got:\n%s", out)
	}
	if !strings.Contains(out, "PasswordAuthentication yes") || !strings.Contains(out, "set PasswordAuthentication no") {
		t.Errorf("a failed rule should show its finding and remediation, got:\n%s", out)
	}
	if !strings.Contains(out, "manual review required") {
		t.Errorf("a manual rule should show its finding, got:\n%s", out)
	}
	if !strings.Contains(out, "3 rules") || !strings.Contains(out, "1 fail") {
		t.Errorf("the summary line should count rules and failures, got:\n%s", out)
	}
	if !strings.Contains(out, "--fail-only") {
		t.Errorf("a report with failures should tip toward --fail-only, got:\n%s", out)
	}
}

func TestPrintCISReportFailOnlyFilter(t *testing.T) {
	report := models.CISReport{
		Profile: "CIS Ubuntu 22.04 LTS Level 1",
		Results: []models.CISResult{
			{ID: "5.2.1", Section: "SSH", Description: "pass rule", Status: models.CISPass},
			{ID: "5.2.2", Section: "SSH", Description: "fail rule", Status: models.CISFail, Finding: "bad config"},
		},
		Pass: 1, Fail: 1,
	}
	out := captureStdout(t, func() { printCISReport(report, true, false, output.ModePlain) })
	if strings.Contains(out, "pass rule") {
		t.Errorf("failOnly=true must suppress passing rules, got:\n%s", out)
	}
	if !strings.Contains(out, "fail rule") {
		t.Errorf("failOnly=true must still show the failing rule, got:\n%s", out)
	}
}

func TestPrintCISReportCleanNoTip(t *testing.T) {
	report := models.CISReport{Profile: "CIS Ubuntu 22.04 LTS Level 1", Pass: 5, Fail: 0}
	out := captureStdout(t, func() { printCISReport(report, false, false, output.ModePlain) })
	if strings.Contains(out, "--fail-only") {
		t.Errorf("a clean report (0 failures) should not show the fail-only tip, got:\n%s", out)
	}
	if !strings.Contains(out, "5 pass") {
		t.Errorf("the pass count should be shown, got:\n%s", out)
	}
}

func TestPrintNIS2ReportFailOnlyFilter(t *testing.T) {
	art := cis.NIS2Article21{ID: "Art.21(2)(b)", Title: "Incident handling"}
	groups := []cis.NIS2ArticleGroup{
		{
			Article: art,
			Status:  "PARTIAL",
			Pass:    1, Fail: 1, Skipped: 1,
			Results: []models.CISResult{
				{ID: "4.1.2", Status: models.CISSkipped, Description: "auditd rules"},
				{ID: "4.2.1", Status: models.CISFail, Description: "rsyslog installed", Finding: "not installed"},
				{ID: "4.2.4", Status: models.CISPass, Description: "rsyslog not accepting remotes"},
			},
		},
	}

	outAll := captureStdout(t, func() { printNIS2Report(groups, false, output.ModePlain) })
	if !strings.Contains(outAll, "auditd rules") {
		t.Errorf("failOnly=false must show SKIP rules, got:\n%s", outAll)
	}
	if !strings.Contains(outAll, "rsyslog not accepting remotes") {
		t.Errorf("failOnly=false must show PASS rules, got:\n%s", outAll)
	}

	outFail := captureStdout(t, func() { printNIS2Report(groups, true, output.ModePlain) })
	if strings.Contains(outFail, "auditd rules") {
		t.Errorf("failOnly=true must suppress SKIP rules, got:\n%s", outFail)
	}
	if strings.Contains(outFail, "rsyslog not accepting remotes") {
		t.Errorf("failOnly=true must suppress PASS rules, got:\n%s", outFail)
	}
	if !strings.Contains(outFail, "rsyslog installed") {
		t.Errorf("failOnly=true must still show FAIL rules, got:\n%s", outFail)
	}
	if !strings.Contains(outFail, "not installed") {
		t.Errorf("failOnly=true must still show FAIL findings, got:\n%s", outFail)
	}
	// per-article summary counts must be unchanged (reflect full evaluation)
	if !strings.Contains(outFail, "1 pass") || !strings.Contains(outFail, "1 fail") {
		t.Errorf("per-article summary counts must be unchanged under failOnly, got:\n%s", outFail)
	}
}

func TestPrintNIS2ReportUnmappedAlwaysShown(t *testing.T) {
	groups := []cis.NIS2ArticleGroup{
		{Article: cis.NIS2Article21{ID: "Art.21(2)(a)", Title: "Risk analysis"}, Status: "UNMAPPED"},
	}
	out := captureStdout(t, func() { printNIS2Report(groups, true, output.ModePlain) })
	if !strings.Contains(out, "Art.21(2)(a)") {
		t.Errorf("UNMAPPED articles must always show regardless of failOnly, got:\n%s", out)
	}
	if !strings.Contains(out, "organisational policy") {
		t.Errorf("UNMAPPED articles must show their explanation, got:\n%s", out)
	}
}
