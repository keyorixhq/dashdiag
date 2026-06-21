package analysis

import (
	"testing"

	"github.com/keyorixhq/dashdiag/internal/models"
	"github.com/keyorixhq/dashdiag/internal/platform"
	"github.com/keyorixhq/dashdiag/internal/runner"
)

// Regression tests for TRIAGE §O — "correct reading, wrong context" false-CRITs
// found on a real AMD EPYC Proxmox host and confirmed false by the owner. Each
// check reads the raw signal correctly; the bug was misattributing its meaning
// because the collector lacked the host/virtualization context.

// §O.1 — a VG that backs a thin pool is ~fully *allocated* to that pool by
// design (Proxmox's default `pve` layout). That must not read as a near-full
// disk; the thin pool's own usage is what matters.
func TestCheckLVMThinBackedVGNotFull(t *testing.T) {
	// The Proxmox default: pve VG 98% allocated, but the `data` thin pool is
	// nearly empty (8% data / 0.5% metadata). Healthy — no VG-full insight.
	pve := models.LVMInfo{
		VGs: []models.LVMVG{
			{Name: "pve", SizeGB: 930.5, FreeGB: 16.0, FreePct: 1.7, HasMountedLV: true},
		},
		ThinPools: []models.LVMThinPool{
			{Name: "data", VG: "pve", DataPct: 8.37, MetaPct: 0.51, SizeGB: 850},
		},
	}
	ins := checkLVM(pve)
	for _, i := range ins {
		if i.Level == "CRIT" || i.Level == "WARN" {
			t.Errorf("§O.1: thin-pool-backed VG must not raise a VG-full alarm, got %s: %q", i.Level, i.Message)
		}
	}

	// Regression: a real near-full VG that does NOT back a thin pool still CRITs.
	plain := models.LVMInfo{
		VGs: []models.LVMVG{
			{Name: "vg0", SizeGB: 100, FreeGB: 1, FreePct: 1, HasMountedLV: true},
		},
	}
	if !hasInsightMsg(checkLVM(plain), "CRIT", "volume group vg0") {
		t.Errorf("§O.1: a genuinely near-full non-thin VG must still CRIT, got: %+v", checkLVM(plain))
	}

	// Regression: thin pool data exhaustion is the real CRIT and is unaffected.
	full := models.LVMInfo{
		ThinPools: []models.LVMThinPool{{Name: "data", VG: "pve", DataPct: 96, SizeGB: 850}},
	}
	if !hasLevel(checkLVM(full), "CRIT") {
		t.Errorf("§O.1: a full thin pool must still CRIT, got: %+v", checkLVM(full))
	}
}

// §O.2 — zfs-import-{scan,cache}.service failing is benign when the host imports
// no pools of its own (e.g. the ZFS HBA is passed through to a VM).
func TestCheckSystemdZFSImportNoPools(t *testing.T) {
	// Failed import unit, no host pools → INFO, not CRIT.
	noPools := checkSystemd(models.SystemdInfo{
		Available:       true,
		FailedUnits:     []string{"zfs-import-scan.service"},
		ZFSPoolsPresent: false,
	})
	if hasInsightMsg(noPools, "CRIT", "has failed") {
		t.Errorf("§O.2: zfs-import failure with no host pools must not CRIT, got: %+v", noPools)
	}
	if !hasInsightMsg(noPools, "INFO", "no ZFS pools are imported") {
		t.Errorf("§O.2: expected a benign INFO explaining the passthrough case, got: %+v", noPools)
	}

	// Same unit, but the host DOES import pools → real CRIT.
	withPools := checkSystemd(models.SystemdInfo{
		Available:       true,
		FailedUnits:     []string{"zfs-import-cache.service"},
		ZFSPoolsPresent: true,
	})
	if !hasInsightMsg(withPools, "CRIT", "has failed") {
		t.Errorf("§O.2: zfs-import failure WITH host pools must CRIT, got: %+v", withPools)
	}

	// A non-ZFS failed unit is unaffected — still CRIT even with no pools.
	other := checkSystemd(models.SystemdInfo{
		Available:   true,
		FailedUnits: []string{"nginx.service"},
	})
	if !hasInsightMsg(other, "CRIT", "has failed") {
		t.Errorf("§O.2: a normal failed unit must still CRIT, got: %+v", other)
	}
}

// §O.2 end-to-end — the ApplyThresholds pre-scan must derive ZFSPoolsPresent
// from the ZFS collector and inject it into SystemdInfo before checkSystemd runs.
func TestApplyThresholdsZFSPoolPrescanGatesImportUnit(t *testing.T) {
	// The pre-scan keys on the result Name, so build properly-named results
	// (res() hardcodes Name:"test" and would skip the Systemd injection).
	withZFS := func(zfs *models.ZFSInfo) []runner.Result {
		return []runner.Result{
			{Name: "Systemd", Data: &models.SystemdInfo{Available: true, FailedUnits: []string{"zfs-import-scan.service"}}},
			{Name: "ZFS", Data: zfs},
		}
	}

	// No pools collected → benign INFO.
	got := ApplyThresholds(
		withZFS(&models.ZFSInfo{}),
		defaultThresh, platform.EnvBareMetal, platform.ContainerContext{},
	)
	if hasInsightMsg(got, "CRIT", "zfs-import-scan.service has failed") {
		t.Errorf("§O.2 e2e: no host pools should gate the CRIT, got: %+v", got)
	}

	// Pools present → CRIT survives the pre-scan.
	got = ApplyThresholds(
		withZFS(&models.ZFSInfo{Pools: []models.ZFSPool{{Name: "tank", State: "ONLINE"}}}),
		defaultThresh, platform.EnvBareMetal, platform.ContainerContext{},
	)
	if !hasInsightMsg(got, "CRIT", "zfs-import-scan.service has failed") {
		t.Errorf("§O.2 e2e: a real host pool should keep the CRIT, got: %+v", got)
	}
}

// §O.3 — the journal-verify collector only checks archived (*.journal~) segments
// (active journals race with live writers, systemd#35916), so a hit is always a
// historical artifact. It must WARN, not CRIT "logs may be missing".
func TestCheckJournalArchivedCorruptionIsWarn(t *testing.T) {
	out := checkJournalConfig(models.LogsInfo{JournalCorrupt: true})
	if hasLevel(out, "CRIT") {
		t.Errorf("§O.3: archived-journal corruption must not CRIT, got: %+v", out)
	}
	if !hasInsightMsg(out, "WARN", "archived") {
		t.Errorf("§O.3: expected a WARN naming the archived segment, got: %+v", out)
	}
}
