package cmd

import (
	"context"
	"strings"
	"testing"

	"github.com/keyorixhq/dashdiag/internal/models"
	"github.com/keyorixhq/dashdiag/internal/output"
)

// Golden-output tests for the printPVE* section renderers. Unlike guest.go's
// *GuestView builders, these take plain data structs (no live collector call),
// so they're directly testable via captureStdout — no extraction needed.

func TestPrintPVENodeSubscription(t *testing.T) {
	cases := []struct {
		name string
		sub  models.PVESubscription
		want string
	}{
		{"active with product", models.PVESubscription{Status: "active", Product: "Proxmox VE Standard Subscription"}, "active (Proxmox VE Standard Subscription)"},
		{"active no product", models.PVESubscription{Status: "active"}, "active"},
		{"not found", models.PVESubscription{Status: "notfound"}, "no subscription (community edition)"},
		{"empty status", models.PVESubscription{}, "no subscription (community edition)"},
		{"expired", models.PVESubscription{Status: "expired"}, "subscription expired"},
		{"unverified", models.PVESubscription{Status: "unverified"}, "configured, live status not verified"},
	}
	for _, c := range cases {
		info := &models.PVEInfo{UptimeSec: 100, Subscription: c.sub}
		out := captureStdout(t, func() { printPVENode(info, output.ModePlain) })
		if !strings.Contains(out, c.want) {
			t.Errorf("%s: printPVENode output missing %q, got:\n%s", c.name, c.want, out)
		}
	}
}

func TestPrintPVEGuestsNone(t *testing.T) {
	out := captureStdout(t, func() { printPVEGuests(&models.PVEInfo{GuestsVerified: true}, output.ModePlain) })
	if !strings.Contains(out, "none") {
		t.Errorf("no guests should report none, got:\n%s", out)
	}
}

// TestPrintPVEGuestsEnumerationFailed guards internal-models-11-02: a zero
// guest count with GuestsVerified=false means the pvesh qemu/lxc query
// itself failed, not that the node genuinely has no VMs/CTs — it must not
// print the same "none" a real guest-less node gets.
func TestPrintPVEGuestsEnumerationFailed(t *testing.T) {
	out := captureStdout(t, func() { printPVEGuests(&models.PVEInfo{GuestsVerified: false}, output.ModePlain) })
	if strings.Contains(out, "]  none") {
		t.Errorf("a failed guest enumeration must not print the clean 'none' line, got:\n%s", out)
	}
	if !strings.Contains(out, "NOT verified") {
		t.Errorf("a failed guest enumeration must disclose NOT verified, got:\n%s", out)
	}
}

func TestPrintPVEGuestsStatusNotes(t *testing.T) {
	cases := []struct {
		name string
		g    models.PVEGuest
		want string
	}{
		{"paused", models.PVEGuest{Status: "paused"}, "unexpected pause"},
		{"stopped, autostart on", models.PVEGuest{Status: "stopped", OnBoot: true}, "autostart ON"},
		{"stopped, autostart off", models.PVEGuest{Status: "stopped", OnBoot: false}, "autostart OFF"},
	}
	for _, c := range cases {
		info := &models.PVEInfo{RunningCount: 0, StoppedCount: 1, Guests: []models.PVEGuest{c.g}}
		out := captureStdout(t, func() { printPVEGuests(info, output.ModePlain) })
		if !strings.Contains(out, c.want) {
			t.Errorf("%s: printPVEGuests output missing %q, got:\n%s", c.name, c.want, out)
		}
	}
}

// TestPrintPVEGuestsOvercommit pins the vCPU/memory overcommit icon thresholds
// (>4x vCPU or >100% memory = WARN, >8x or >150% = CRIT) so `dsd pve` can't
// silently stop flagging an overcommitted node.
func TestPrintPVEGuestsOvercommit(t *testing.T) {
	cases := []struct {
		name          string
		vcpus, cores  int
		totalMem, ram float64
		wantIcon      string
	}{
		{"vCPU ok", 4, 4, 0, 0, "OK"},
		{"vCPU warn", 20, 4, 0, 0, "WARN"}, // 5:1
		{"vCPU crit", 40, 4, 0, 0, "CRIT"}, // 10:1
		{"mem ok", 0, 0, 8, 16, "OK"},      // 50%
		{"mem warn", 0, 0, 18, 16, "WARN"}, // 112%
		{"mem crit", 0, 0, 30, 16, "CRIT"}, // 187%
	}
	for _, c := range cases {
		info := &models.PVEInfo{
			RunningCount: 1, PhysicalCores: c.cores, TotalVCPUs: c.vcpus,
			HostMemGB: c.ram, TotalMemGB: c.totalMem,
		}
		out := strings.TrimSpace(captureStdout(t, func() { printPVEGuests(info, output.ModePlain) }))
		if !strings.Contains(out, c.wantIcon) {
			t.Errorf("%s: expected %s icon in output, got:\n%s", c.name, c.wantIcon, out)
		}
	}
}

func TestPrintPVEStorage(t *testing.T) {
	cases := []struct {
		name    string
		s       models.PVEStorage
		want    string
		notWant string
	}{
		{"inactive", models.PVEStorage{Name: "local", Active: false}, "UNAVAILABLE", ""},
		{"healthy", models.PVEStorage{Name: "local", Active: true, UsedPct: 50}, "local", "CRIT"},
		{"warn band", models.PVEStorage{Name: "local", Active: true, UsedPct: 82}, "82% full", "CRIT"},
		{"crit band", models.PVEStorage{Name: "local", Active: true, UsedPct: 95}, "CRIT: 95% full", ""},
		{"with size", models.PVEStorage{Name: "local", Active: true, UsedPct: 50, TotalGB: 200, UsedGB: 100}, "100 / 200 GB", ""},
	}
	for _, c := range cases {
		info := &models.PVEInfo{Storages: []models.PVEStorage{c.s}}
		out := captureStdout(t, func() { printPVEStorage(info, output.ModePlain) })
		if !strings.Contains(out, c.want) {
			t.Errorf("%s: printPVEStorage output missing %q, got:\n%s", c.name, c.want, out)
		}
		if c.notWant != "" && strings.Contains(out, c.notWant) {
			t.Errorf("%s: printPVEStorage output must not contain %q, got:\n%s", c.name, c.notWant, out)
		}
	}
}

func TestPrintPVETaskErrors(t *testing.T) {
	none := captureStdout(t, func() { printPVETaskErrors(&models.PVEInfo{}, output.ModePlain) })
	if !strings.Contains(none, "No task errors") {
		t.Errorf("no task errors should say so, got:\n%s", none)
	}

	// 3+ of the same type escalates to CRIT; below that stays WARN.
	info := &models.PVEInfo{TaskErrors: []models.PVETaskError{
		{Type: "vzdump", Msg: "err1"}, {Type: "vzdump", Msg: "err2"}, {Type: "vzdump", Msg: "err3"},
		{Type: "qmigrate", Msg: "err4"},
	}}
	out := captureStdout(t, func() { printPVETaskErrors(info, output.ModePlain) })
	if got := strings.Count(out, "CRIT"); got != 3 {
		t.Errorf("3 vzdump errors should each render CRIT, got %d CRIT occurrences in:\n%s", got, out)
	}
	if !strings.Contains(out, "WARN") {
		t.Errorf("the lone qmigrate error should render WARN, got:\n%s", out)
	}
}

func TestPrintPVECluster(t *testing.T) {
	// Single-node, no cluster configured: section is entirely suppressed.
	none := captureStdout(t, func() { printPVECluster(&models.PVEInfo{}, output.ModePlain) })
	if none != "" {
		t.Errorf("no cluster name/nodes should print nothing, got:\n%s", none)
	}

	quorateOK := captureStdout(t, func() {
		printPVECluster(&models.PVEInfo{ClusterName: "prod", QuorumOK: true}, output.ModePlain)
	})
	if !strings.Contains(quorateOK, "Quorate: yes") {
		t.Errorf("quorate cluster should say yes, got:\n%s", quorateOK)
	}

	splitBrain := captureStdout(t, func() {
		printPVECluster(&models.PVEInfo{ClusterName: "prod", QuorumOK: false}, output.ModePlain)
	})
	if !strings.Contains(splitBrain, "split-brain risk") {
		t.Errorf("non-quorate cluster must warn of split-brain risk, got:\n%s", splitBrain)
	}

	offlineNode := captureStdout(t, func() {
		printPVECluster(&models.PVEInfo{
			ClusterName: "prod", QuorumOK: true,
			Nodes: []models.PVENode{{Name: "pve02", Online: false}},
		}, output.ModePlain)
	})
	if !strings.Contains(offlineNode, "OFFLINE") {
		t.Errorf("an offline node must be flagged, got:\n%s", offlineNode)
	}
}

func TestPrintPVEBackupDispatch(t *testing.T) {
	// Per-VM audit present: must use the per-VM path (VMID/name shown), not the
	// global BackupAgeDays fallback.
	perVM := captureStdout(t, func() {
		printPVEBackup(&models.PVEInfo{
			BackupAgeDays:  99, // would render CRIT via the global path if wrongly taken
			BackupStatuses: []models.PVEBackupStatus{{VMID: 100, Name: "web01", LastBackupDays: 0}},
		}, output.ModePlain)
	})
	if !strings.Contains(perVM, "web01") {
		t.Errorf("per-VM backup audit should list the VM by name, got:\n%s", perVM)
	}
	if strings.Contains(perVM, "99 days ago") {
		t.Errorf("per-VM audit present must not fall back to the global BackupAgeDays, got:\n%s", perVM)
	}

	never := captureStdout(t, func() {
		printPVEBackup(&models.PVEInfo{BackupAgeDays: -1}, output.ModePlain)
	})
	if !strings.Contains(never, "No successful backup found") {
		t.Errorf("BackupAgeDays -1 should report never backed up, got:\n%s", never)
	}
}

func TestPrintPVEPerf(t *testing.T) {
	if out := captureStdout(t, func() { printPVEPerf(nil, output.ModePlain) }); out != "" {
		t.Errorf("nil perf should print nothing, got:\n%s", out)
	}

	unavailable := captureStdout(t, func() {
		printPVEPerf(&models.PVEPerf{Available: false}, output.ModePlain)
	})
	if !strings.Contains(unavailable, "pveperf not found") {
		t.Errorf("unavailable pveperf should say not found, got:\n%s", unavailable)
	}

	// Buffered reads below 50 MB/s = CRIT, below 200 = WARN.
	slow := captureStdout(t, func() {
		printPVEPerf(&models.PVEPerf{Available: true, BufferedReadMB: 30}, output.ModePlain)
	})
	if !strings.Contains(slow, "CRIT") {
		t.Errorf("30 MB/s buffered reads should be CRIT, got:\n%s", slow)
	}

	// Fsyncs/sec below 100 = CRIT (VM stability risk on this storage).
	fsyncCrit := captureStdout(t, func() {
		printPVEPerf(&models.PVEPerf{Available: true, FsyncsPerSec: 50}, output.ModePlain)
	})
	if !strings.Contains(fsyncCrit, "CRIT") {
		t.Errorf("50 fsyncs/sec should be CRIT, got:\n%s", fsyncCrit)
	}
}

// TestPrintPVEPerfHealthyAndFsyncWarn covers the OK-icon branches of
// BufferedReadMB/FsyncsPerSec (values above their WARN bands) and the
// FsyncsPerSec WARN band (100–500), none exercised by the CRIT-only cases above.
func TestPrintPVEPerfHealthyAndFsyncWarn(t *testing.T) {
	healthy := captureStdout(t, func() {
		printPVEPerf(&models.PVEPerf{Available: true, BufferedReadMB: 400, FsyncsPerSec: 800}, output.ModePlain)
	})
	if !strings.Contains(healthy, "OK") {
		t.Errorf("healthy buffered-read and fsync rates should render OK, got:\n%s", healthy)
	}
	if strings.Contains(healthy, "WARN") || strings.Contains(healthy, "CRIT") {
		t.Errorf("healthy values must not also render WARN/CRIT, got:\n%s", healthy)
	}

	fsyncWarn := captureStdout(t, func() {
		printPVEPerf(&models.PVEPerf{Available: true, FsyncsPerSec: 300}, output.ModePlain)
	})
	if !strings.Contains(fsyncWarn, "WARN") {
		t.Errorf("300 fsyncs/sec (100-500 band) should be WARN, got:\n%s", fsyncWarn)
	}

	readWarn := captureStdout(t, func() {
		printPVEPerf(&models.PVEPerf{Available: true, BufferedReadMB: 100}, output.ModePlain)
	})
	if !strings.Contains(readWarn, "WARN") {
		t.Errorf("100 MB/s buffered reads (50-200 band) should be WARN, got:\n%s", readWarn)
	}
}

func TestPrintPVEBridges(t *testing.T) {
	down := captureStdout(t, func() {
		printPVEBridges(&models.PVEInfo{Bridges: []models.PVEBridge{{Name: "vmbr0", Active: false}}}, output.ModePlain)
	})
	if !strings.Contains(down, "DOWN") {
		t.Errorf("a down bridge must say DOWN, got:\n%s", down)
	}

	noUplink := captureStdout(t, func() {
		printPVEBridges(&models.PVEInfo{Bridges: []models.PVEBridge{{Name: "vmbr1", Active: true, HasUplink: false}}}, output.ModePlain)
	})
	if !strings.Contains(noUplink, "no uplink") {
		t.Errorf("a bridge with no uplink must be flagged, got:\n%s", noUplink)
	}

	stpOn := captureStdout(t, func() {
		printPVEBridges(&models.PVEInfo{Bridges: []models.PVEBridge{{Name: "vmbr0", Active: true, HasUplink: true, STPEnabled: true}}}, output.ModePlain)
	})
	if !strings.Contains(stpOn, "STP: ON") || !strings.Contains(stpOn, "boot delay") {
		t.Errorf("STP enabled should warn of boot delay, got:\n%s", stpOn)
	}
}

// TestPrintPVEBridges_QueryFailedNotSilentlyEmpty guards internal-models-11-03:
// every real PVE node has at least one bridge, so an empty Bridges slice with
// BridgesVerified=false must disclose the query failure rather than printing
// nothing — indistinguishable from a section that was never meant to appear.
func TestPrintPVEBridges_QueryFailedNotSilentlyEmpty(t *testing.T) {
	out := captureStdout(t, func() {
		printPVEBridges(&models.PVEInfo{Bridges: nil, BridgesVerified: false}, output.ModePlain)
	})
	if !strings.Contains(out, "NOT verified") {
		t.Errorf("a failed bridge query must disclose NOT verified, got:\n%s", out)
	}
}

// TestPrintPVEBridges_VerifiedEmptyStaysSilent is the non-regression
// counterpart: BridgesVerified=true with a genuinely empty list (should not
// happen on a real node, but the collector contract allows it) must NOT print
// a false "not verified" disclosure.
func TestPrintPVEBridges_VerifiedEmptyStaysSilent(t *testing.T) {
	out := captureStdout(t, func() {
		printPVEBridges(&models.PVEInfo{Bridges: nil, BridgesVerified: true}, output.ModePlain)
	})
	if out != "" {
		t.Errorf("a verified-empty bridge list must stay silent, got:\n%s", out)
	}
}

// TestPrintPVEReportSummary pins the top-level healthy/concern verdict text and
// the API-unreachable up-front warning — the same "issues==0 -> healthy" tally
// shape as the cmd verdict tally drift class elsewhere in cmd/.
func TestPrintPVEReportSummary(t *testing.T) {
	healthy := captureStdout(t, func() {
		printPVEReport(&models.PVEInfo{IsPVE: true, APIReachable: true}, false, 0, output.ModePlain)
	})
	if !strings.Contains(healthy, "Proxmox VE healthy") {
		t.Errorf("no concerns should read healthy, got:\n%s", healthy)
	}

	unreachable := captureStdout(t, func() {
		printPVEReport(&models.PVEInfo{IsPVE: true, NeedsRoot: false, APIReachable: false}, false, 0, output.ModePlain)
	})
	if !strings.Contains(unreachable, "not responding") {
		t.Errorf("unreachable pvesh API must be surfaced up front, got:\n%s", unreachable)
	}
	if strings.Contains(unreachable, "Proxmox VE healthy") {
		t.Errorf("an unreachable API must not read healthy, got:\n%s", unreachable)
	}

	concern := captureStdout(t, func() {
		printPVEReport(&models.PVEInfo{
			IsPVE: true, APIReachable: true,
			Storages: []models.PVEStorage{{Name: "local", Active: true, UsedPct: 95}},
		}, false, 0, output.ModePlain)
	})
	if !strings.Contains(concern, "concern(s) found") {
		t.Errorf("a full storage pool should surface as a concern, got:\n%s", concern)
	}
}

// TestPrintPVENodeFields covers the version/kernel host line, the CPU/cores/
// memory/uptime lines (all suppressed when their zero-value trigger is not
// met), which the subscription-focused test above doesn't reach.
func TestPrintPVENodeFields(t *testing.T) {
	minimal := captureStdout(t, func() {
		printPVENode(&models.PVEInfo{}, output.ModePlain)
	})
	if strings.Contains(minimal, "Host:") || strings.Contains(minimal, "CPU:") ||
		strings.Contains(minimal, "Cores:") || strings.Contains(minimal, "Memory:") || strings.Contains(minimal, "Uptime:") {
		t.Errorf("an empty PVEInfo should suppress every optional node line, got:\n%s", minimal)
	}

	full := captureStdout(t, func() {
		printPVENode(&models.PVEInfo{
			PVEVersion: "8.1.4", KernelVersion: "6.5.11-7-pve",
			UptimeSec: 90000, PhysicalCores: 16, HostMemGB: 64, CPUPct: 12,
		}, output.ModePlain)
	})
	if !strings.Contains(full, "PVE 8.1.4") || !strings.Contains(full, "kernel 6.5.11-7-pve") {
		t.Errorf("version and kernel should both appear on the host line, got:\n%s", full)
	}
	if !strings.Contains(full, "16 cores") || !strings.Contains(full, "64.0 GB") {
		t.Errorf("cores and memory should be shown, got:\n%s", full)
	}
}

// TestPrintPVEBackupAgeBands covers every branch of the global BackupAgeDays
// switch (used when no per-VM BackupStatuses audit is present).
func TestPrintPVEBackupAgeBands(t *testing.T) {
	cases := []struct {
		days int
		want string
	}{
		{0, "today"},
		{1, "yesterday"},
		{5, "5 days ago"},
		{20, "20 days ago"},
		{45, "45 days ago"}, // beyond 30 days: default CRIT band
	}
	for _, c := range cases {
		out := captureStdout(t, func() { printPVEBackup(&models.PVEInfo{BackupAgeDays: c.days}, output.ModePlain) })
		if !strings.Contains(out, c.want) {
			t.Errorf("BackupAgeDays=%d: printPVEBackup output missing %q, got:\n%s", c.days, c.want, out)
		}
	}
}

// TestPrintPVEPerfThresholds covers the AvgSeekMs/CPUBogomips/DNSExtMs metric
// branches (BufferedReadMB and FsyncsPerSec CRIT bands are already covered by
// TestPrintPVEPerf).
func TestPrintPVEPerfThresholds(t *testing.T) {
	warnSeek := captureStdout(t, func() {
		printPVEPerf(&models.PVEPerf{Available: true, AvgSeekMs: 5}, output.ModePlain)
	})
	if !strings.Contains(warnSeek, "WARN") {
		t.Errorf("a 5ms avg seek (>2ms) should be WARN, got:\n%s", warnSeek)
	}
	critSeek := captureStdout(t, func() {
		printPVEPerf(&models.PVEPerf{Available: true, AvgSeekMs: 15}, output.ModePlain)
	})
	if !strings.Contains(critSeek, "CRIT") {
		t.Errorf("a 15ms avg seek (>10ms) should be CRIT, got:\n%s", critSeek)
	}
	bogomips := captureStdout(t, func() {
		printPVEPerf(&models.PVEPerf{Available: true, CPUBogomips: 45000}, output.ModePlain)
	})
	if !strings.Contains(bogomips, "45000") {
		t.Errorf("CPU bogomips should be shown, got:\n%s", bogomips)
	}
	slowDNS := captureStdout(t, func() {
		printPVEPerf(&models.PVEPerf{Available: true, DNSExtMs: 600}, output.ModePlain)
	})
	if !strings.Contains(slowDNS, "WARN") {
		t.Errorf("a 600ms external DNS (>500ms) should be WARN, got:\n%s", slowDNS)
	}
}

// TestCountPVEIssuesExtras covers the bridges, vCPU-ratio, memory-ratio, and
// per-VM-backup-audit contributions to the concern tally (storage is already
// covered by TestCountPVEIssuesStorageThreshold in pve_test.go).
func TestCountPVEIssuesExtras(t *testing.T) {
	bridges := countPVEIssues(&models.PVEInfo{Bridges: []models.PVEBridge{{Name: "vmbr0", Active: false}}})
	if bridges != 1 {
		t.Errorf("a down bridge should count as 1 issue, got %d", bridges)
	}
	vcpuRatio := countPVEIssues(&models.PVEInfo{PhysicalCores: 4, TotalVCPUs: 20, Guests: []models.PVEGuest{{}}})
	if vcpuRatio != 1 {
		t.Errorf("a >4:1 vCPU overcommit should count as 1 issue, got %d", vcpuRatio)
	}
	memRatio := countPVEIssues(&models.PVEInfo{HostMemGB: 16, TotalMemGB: 20})
	if memRatio != 1 {
		t.Errorf("assigned memory exceeding host RAM should count as 1 issue, got %d", memRatio)
	}
	perVMBackups := countPVEIssues(&models.PVEInfo{BackupStatuses: []models.PVEBackupStatus{
		{VMID: 100, LastBackupDays: 30}, {VMID: 101, LastBackupDays: -1},
	}})
	if perVMBackups != 2 {
		t.Errorf("2 stale/never per-VM backups should count as 2 issues, got %d", perVMBackups)
	}
	// A stopped guest with autostart ON is unexpected (should be running) — 1 issue.
	stoppedOnBoot := countPVEIssues(&models.PVEInfo{Guests: []models.PVEGuest{{Status: "stopped", OnBoot: true}}})
	if stoppedOnBoot != 1 {
		t.Errorf("a stopped autostart guest should count as 1 issue, got %d", stoppedOnBoot)
	}
	// A named cluster that's not quorate is a split-brain risk — 1 issue.
	notQuorate := countPVEIssues(&models.PVEInfo{ClusterName: "pve-cluster", QuorumOK: false})
	if notQuorate != 1 {
		t.Errorf("a non-quorate cluster should count as 1 issue, got %d", notQuorate)
	}
	// The global BackupAgeDays fallback path (no per-VM audit) must also count
	// a stale backup as an issue.
	globalStaleBackup := countPVEIssues(&models.PVEInfo{BackupAgeDays: 45})
	if globalStaleBackup != 1 {
		t.Errorf("a stale global backup age should count as 1 issue, got %d", globalStaleBackup)
	}
}

// TestRunPVE exercises runPVE's real (read-only) IsPVEHost gate in --plain and
// --json mode. This test host is not a Proxmox node, so both should take the
// short-circuit "not a PVE node" path without error — the same real-I/O
// precedent as cpu_report_test.go / hardware_test.go.
func TestRunPVE(t *testing.T) {
	plainCmd := newBareCloudCmd()
	plainCmd.SetContext(context.Background())
	_ = plainCmd.Flags().Set("plain", "true")
	plainOut := captureStdout(t, func() {
		if err := runPVE(plainCmd, nil); err != nil {
			t.Fatalf("runPVE (plain): %v", err)
		}
	})
	if !strings.Contains(plainOut, "Proxmox VE") {
		t.Errorf("the not-a-PVE-node message should mention Proxmox VE, got: %q", plainOut)
	}

	jsonCmd := newBareCloudCmd()
	jsonCmd.SetContext(context.Background())
	_ = jsonCmd.Flags().Set("json", "true")
	jsonOut := captureStdout(t, func() {
		if err := runPVE(jsonCmd, nil); err != nil {
			t.Fatalf("runPVE (json): %v", err)
		}
	})
	if jsonOut == "" {
		t.Error("runPVE (json, not a PVE node) should still print the info message")
	}
}
