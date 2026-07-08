package cmd

import (
	"strings"
	"testing"
	"time"

	"github.com/keyorixhq/dashdiag/internal/models"
	"github.com/keyorixhq/dashdiag/internal/output"
)

// falseok_verdict_test.go — the canonical guard for the "unverified-state false-OK"
// class: a standalone `dsd <cmd>` renderer printing its green all-clear
// ("healthy" / "Checks passed" / "none") when the underlying probe never actually
// ran (API unreachable, log unreadable, non-root, systemctl absent, …).
//
// WHY THIS NEEDS ITS OWN GUARD (and cmd_health_consistency_test.go can't catch it):
// that test compares WARN/CRIT *concern* parity between `dsd <cmd>` and `dsd health`.
// An unverified state produces an INFO in health and a green OK in the cmd renderer —
// BOTH register as "no concern", so a concern-parity check is blind to it. The bug is
// "green-OK vs honest-INFO", which is only observable at the rendered-output level.
// (Root cause: cmd renderers and health heuristics are SEPARATE consumers of the same
// collector struct; a false-OK fix applied to the heuristic, e.g. k8s APIReachable in
// #210, did not propagate to the renderer until #575/#576.)
//
// CONVENTION — when you add an "unverified" signal to a collector (a field like
// *Verified / *Unreadable / *Queried / *Reachable / NeedsRoot / ScanFailed /
// *ReadFailed) AND a standalone renderer that can show an all-clear, add a case here
// asserting the renderer does NOT show the all-clear when the signal says unverified
// (and the inverse: a genuinely-verified clean state still reads OK). The durable fix
// is to route the renderer's verdict through the same heuristic health uses (as
// `dsd security` does) so the two cannot diverge by construction.
//
// Guarded (command → unverified flag): k8s → APIReachable; cron → FailureScanOK;
// logs → ErrorCountUnverified / NeedsRoot; services deep → FailedUnitsQueried.
// (cve --all → ScanFailed is guarded in cve_scanfailed_test.go.)

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

// services deep: on a non-systemd host (or when systemctl errors) the failed-units
// query never runs, so FailedUnits is empty NOT because there are none. The renderer
// must not print the green "Failed units: none".
func TestServicesDeepNotQueriedNotNone(t *testing.T) {
	notQueried := &models.ServicesDeepInfo{FailedUnitsQueried: false, JournalHealthy: true}
	out := captureStdout(t, func() { printSystemdHealth(notQueried, output.ModeHuman) })
	if line := failedUnitsLine(out); !strings.Contains(line, "not queried") {
		t.Errorf("un-queried systemd 'Failed units' line should say 'not queried', got %q", line)
	}
	queried := &models.ServicesDeepInfo{FailedUnitsQueried: true, JournalHealthy: true}
	out2 := captureStdout(t, func() { printSystemdHealth(queried, output.ModeHuman) })
	if line := failedUnitsLine(out2); !strings.Contains(line, "none") {
		t.Errorf("queried-with-no-failures 'Failed units' line should say 'none', got %q", line)
	}
}

// failedUnitsLine returns the rendered "Failed units" line (other lines also contain
// "none"/"healthy", so assertions must target this line specifically).
func failedUnitsLine(out string) string {
	for l := range strings.SplitSeq(out, "\n") {
		if strings.Contains(l, "Failed units") {
			return l
		}
	}
	return ""
}
