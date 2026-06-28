package cmd

import (
	"strings"
	"testing"
	"time"

	"github.com/keyorixhq/dashdiag/internal/models"
	"github.com/keyorixhq/dashdiag/internal/output"
)

// These guard a false-OK class found by auditing standalone-command verdicts: the
// `dsd health` heuristic gates on an "unverified" flag, but the standalone command's
// renderer ignored that same flag and printed a green "Checks passed"/"healthy"/"none"
// when the probe never actually ran. Same shape as the cve --all ScanFailed bug.

// k8s: kubectl/k3s present but the cluster API was never reached (Detected &&
// !APIReachable) — every count is 0 because nothing was queried. Must not read OK.
func TestK8sReportUnreachableNotHealthy(t *testing.T) {
	info := &models.K8sInfo{Detected: true, KubeBin: "kubectl", APIReachable: false}
	out := captureStdout(t, func() { printK8sReport(info, output.ModeHuman, 0) })
	if strings.Contains(out, "Cluster healthy") || strings.Contains(out, "All pods healthy") {
		t.Errorf("unreachable cluster must not render healthy; got:\n%s", out)
	}
	if !strings.Contains(out, "NOT verified") {
		t.Errorf("unreachable cluster should say NOT verified; got:\n%s", out)
	}
	// A reachable, clean cluster still reads healthy.
	ok := &models.K8sInfo{Detected: true, KubeBin: "kubectl", APIReachable: true}
	out2 := captureStdout(t, func() { printK8sReport(ok, output.ModeHuman, 0) })
	if !strings.Contains(out2, "Cluster healthy") {
		t.Errorf("reachable clean cluster should read healthy; got:\n%s", out2)
	}
}

// cron: failure history unreadable (FailureScanOK==false) → an empty Failures list
// means "couldn't look", not "none". Must not render the green "none".
func TestCronReportUnreadableFailures(t *testing.T) {
	unreadable := &models.CronInfo{DaemonActive: true, FailureScanOK: false}
	out := captureStdout(t, func() { printCron(unreadable, output.ModeHuman) })
	if !strings.Contains(out, "not readable") {
		t.Errorf("unreadable cron failure history must say so, not 'none'; got:\n%s", out)
	}
	readable := &models.CronInfo{DaemonActive: true, FailureScanOK: true}
	out2 := captureStdout(t, func() { printCron(readable, output.ModeHuman) })
	if !strings.Contains(out2, "none") {
		t.Errorf("readable-with-no-failures should render 'none'; got:\n%s", out2)
	}
}

// logs: error history unverified (ErrorCountUnverified) or a non-root run must not
// assert "Logs healthy. Checks passed" — OOM/segfault/error scans were incomplete.
func TestLogsReportUnverifiedNotHealthy(t *testing.T) {
	unver := &models.LogsInfo{Available: true, ErrorCountUnverified: true}
	out := captureStdout(t, func() { printLogsReport(unver, output.ModeHuman, 0, time.Hour) })
	if strings.Contains(out, "Checks passed") {
		t.Errorf("unverified error history must not say 'Checks passed'; got:\n%s", out)
	}
	if !strings.Contains(out, "NOT verified") {
		t.Errorf("unverified error history should say NOT verified; got:\n%s", out)
	}

	nonRoot := &models.LogsInfo{Available: true, NeedsRoot: true}
	out2 := captureStdout(t, func() { printLogsReport(nonRoot, output.ModeHuman, 0, time.Hour) })
	if strings.Contains(out2, "Checks passed") {
		t.Errorf("non-root run must not assert a clean 'Checks passed'; got:\n%s", out2)
	}

	full := &models.LogsInfo{Available: true} // root, everything readable
	out3 := captureStdout(t, func() { printLogsReport(full, output.ModeHuman, 0, time.Hour) })
	if !strings.Contains(out3, "Checks passed") {
		t.Errorf("fully-verified clean logs should read 'Checks passed'; got:\n%s", out3)
	}
}
