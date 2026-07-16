package analysis

import (
	"strings"
	"testing"

	"github.com/keyorixhq/dashdiag/internal/models"
)

// TestCheckSessions_UniqueIPs covers the len(s.UniqueIPs) > 1 INFO branch in
// checkSessions — multiple distinct remote IPs must surface as an informational note.
func TestCheckSessions_UniqueIPs(t *testing.T) {
	t.Parallel()
	s := models.SessionsInfo{
		TotalCount:  2,
		RemoteCount: 2,
		UniqueIPs:   []string{"10.0.0.1", "10.0.0.2"},
	}
	got := checkSessions(s)
	if !hasInsightMsg(got, "INFO", "2 unique IP") {
		t.Errorf("multiple unique IPs must produce an INFO insight, got %+v", got)
	}
}

// TestCheckJournalActivity_CrashFileListing covers the CrashFiles loop body in
// checkJournalActivity — when crash files are known, their paths must appear in
// the insight hints alongside the count.
func TestCheckJournalActivity_CrashFileListing(t *testing.T) {
	t.Parallel()
	logs := models.LogsInfo{
		CoreDumpCount: 2,
		CrashFiles: []models.CrashFile{
			{Path: "/var/crash/core.1234", SizeMB: 12.5, AgeDays: 3},
		},
	}
	got := checkJournalActivity(logs)
	if !hasInsightMsg(got, "WARN", "crash dump") {
		t.Fatalf("CoreDumpCount > 0 must WARN, got %+v", got)
	}
	found := false
	for _, ins := range got {
		if strings.Contains(ins.Message, "crash dump") {
			for _, h := range ins.Hints {
				if strings.Contains(h, "/var/crash/core.1234") {
					found = true
				}
			}
		}
	}
	if !found {
		t.Errorf("crash file path must appear in insight hints, got %+v", got)
	}
}

// TestK8sEventInsight_FiveDistinctReasons covers the `if i >= 4 { break }` branch
// inside k8sEventInsight's reason-summary loop — the summary must be capped at 4
// distinct reasons even when more are present.
func TestK8sEventInsight_FiveDistinctReasons(t *testing.T) {
	t.Parallel()
	events := []models.K8sEvent{
		{Reason: "BackOff", Age: "30s"},
		{Reason: "Unhealthy", Age: "30s"},
		{Reason: "FailedScheduling", Age: "30s"},
		{Reason: "OOMKilling", Age: "30s"},
		{Reason: "Evicted", Age: "30s"},
	}
	ins := k8sEventInsight("WARN", events)
	if ins.Level != "WARN" {
		t.Errorf("expected WARN, got %q", ins.Level)
	}
	// The summary format is "Reason×count, …" — must not exceed 4 entries.
	if strings.Count(ins.Message, "×") > 4 {
		t.Errorf("summary must cap at 4 reasons (i>=4 break), got %q", ins.Message)
	}
}

// TestCheckBonding_HighLinkFails covers the s.LinkFails > 10 WARN branch inside
// checkBonding's link-failure scan — a slave with excessive link failures must warn
// even if the bond is only partially degraded (not all-down).
func TestCheckBonding_HighLinkFails(t *testing.T) {
	t.Parallel()
	b := models.BondingInfo{Bonds: []models.BondInterface{{
		Name:      "bond0",
		DownSlaves: 1,
		Slaves: []models.BondSlave{
			{Name: "eth0", State: "up", LinkFails: 50},
			{Name: "eth1", State: "down"},
		},
	}}}
	got := checkBonding(b)
	if !hasInsightMsg(got, "WARN", "50 link failures") {
		t.Errorf("slave with >10 link failures must produce a WARN, got %+v", got)
	}
}

// TestBusyProcessHints_ManyProcesses covers the len(BusyProcesses) > 10 branch
// in busyProcessHints — when more than 10 processes hold a mount open, the hint
// must warn that unmounting without stopping them first is unsafe.
func TestBusyProcessHints_ManyProcesses(t *testing.T) {
	t.Parallel()
	procs := make([]models.FSBusyProcess, 11)
	for i := range procs {
		procs[i] = models.FSBusyProcess{PID: i + 1, Command: "worker", User: "root"}
	}
	fs := models.FilesystemInfo{Mount: "/data", BusyProcesses: procs}
	hints := busyProcessHints(fs)
	found := false
	for _, h := range hints {
		if strings.Contains(h, "too many to unmount safely") {
			found = true
		}
	}
	if !found {
		t.Errorf("11 busy processes must produce riskNote hint, got %v", hints)
	}
}

// TestBusyProcessHints_NeedsRootWithProcesses covers the BusyCheckNeedsRoot branch
// in busyProcessHints when processes ARE found — the unprivileged warning must be
// appended as a final hint even when there are visible processes (the early-return
// branch only fires when no processes were found at all).
func TestBusyProcessHints_NeedsRootWithProcesses(t *testing.T) {
	t.Parallel()
	fs := models.FilesystemInfo{
		Mount:              "/data",
		BusyProcesses:     []models.FSBusyProcess{{PID: 99, Command: "app", User: "root"}},
		BusyCheckNeedsRoot: true,
	}
	hints := busyProcessHints(fs)
	found := false
	for _, h := range hints {
		if strings.Contains(h, "unprivileged") {
			found = true
		}
	}
	if !found {
		t.Errorf("BusyCheckNeedsRoot with visible processes must append unprivileged caveat, got %v", hints)
	}
}
