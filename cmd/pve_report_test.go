package cmd

import (
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
	out := captureStdout(t, func() { printPVEGuests(&models.PVEInfo{}, output.ModePlain) })
	if !strings.Contains(out, "none") {
		t.Errorf("no guests should report none, got:\n%s", out)
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
