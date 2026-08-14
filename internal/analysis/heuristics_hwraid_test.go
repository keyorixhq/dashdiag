package analysis

import (
	"testing"

	"github.com/keyorixhq/dashdiag/internal/models"
)

func TestCheckHWRaid(t *testing.T) {
	if got := checkHWRaid(models.HWRaidInfo{Available: false}); got != nil {
		t.Error("no controller present must be silent")
	}

	// Fully healthy controller — silent.
	healthy := models.HWRaidInfo{Available: true, Tool: "storcli", Controllers: []models.HWRaidController{{
		ID: 0, Model: "MegaRAID 9560",
		VirtualDrives:  []models.HWRaidVD{{Name: "data", State: "Optimal"}},
		PhysicalDrives: []models.HWRaidPD{{Location: "252:0", State: "Online"}},
	}}}
	if got := checkHWRaid(healthy); len(got) != 0 {
		t.Errorf("healthy controller must be silent, got %+v", got)
	}

	// Degraded VD + failed PD → two CRITs; rebuilding PD → WARN.
	degraded := models.HWRaidInfo{Available: true, Tool: "perccli", Controllers: []models.HWRaidController{{
		ID: 0, Model: "PERC H730P",
		VirtualDrives: []models.HWRaidVD{{Name: "DATA", RaidLevel: "RAID5", State: "Degraded", Degraded: true}},
		PhysicalDrives: []models.HWRaidPD{
			{Location: "32:3", State: "Failed", Failed: true},
			{Location: "32:4", State: "Rebuilding", Rebuilding: true},
		},
	}}}
	ins := checkHWRaid(degraded)
	if !hasInsightMsg(ins, "CRIT", "DEGRADED") {
		t.Error("degraded VD must CRIT")
	}
	if !hasInsightMsg(ins, "CRIT", "FAILED") {
		t.Error("failed PD must CRIT")
	}
	if !hasInsightMsg(ins, "WARN", "REBUILDING") {
		t.Error("rebuilding PD must WARN")
	}

	// Offline VD → CRIT.
	offline := models.HWRaidInfo{Available: true, Tool: "storcli", Controllers: []models.HWRaidController{{
		VirtualDrives: []models.HWRaidVD{{Name: "vd0", State: "Offline", Offline: true}},
	}}}
	if !hasInsightMsg(checkHWRaid(offline), "CRIT", "OFFLINE") {
		t.Error("offline VD must CRIT")
	}

	// Predictive-failure PD → WARN (not CRIT — it hasn't failed yet).
	predictive := models.HWRaidInfo{Available: true, Controllers: []models.HWRaidController{{
		PhysicalDrives: []models.HWRaidPD{{Location: "252:1", State: "Predictive Failure", Predictive: true}},
	}}}
	pins := checkHWRaid(predictive)
	if !hasInsightMsg(pins, "WARN", "PREDICTIVE") {
		t.Error("predictive-failure PD must WARN")
	}
	for _, in := range pins {
		if in.Level == "CRIT" {
			t.Error("predictive failure must not CRIT — the drive has not failed yet")
		}
	}

	// Bad cache battery → WARN.
	bbu := models.HWRaidInfo{Available: true, Controllers: []models.HWRaidController{{
		BBUStatus: "Replacement required", BBUDegraded: true,
	}}}
	if !hasInsightMsg(checkHWRaid(bbu), "WARN", "cache battery") {
		t.Error("degraded BBU must WARN")
	}
}

func TestCheckHWRaidHonestDegradation(t *testing.T) {
	// Controller present but root-gated: INFO ("re-run as root"), never healthy/silent
	// and never a WARN/CRIT asserting a state we never read.
	nr := checkHWRaid(models.HWRaidInfo{Available: true, Tool: "storcli", NeedsRoot: true})
	if !hasInsightMsg(nr, "INFO", "root") {
		t.Error("root-gated controller must INFO to re-run as root")
	}
	for _, in := range nr {
		if in.Level == "WARN" || in.Level == "CRIT" {
			t.Errorf("needs-root must not WARN/CRIT, got %s", in.Level)
		}
	}
	// Unparseable output: INFO unverified, not healthy.
	rf := checkHWRaid(models.HWRaidInfo{Available: true, Tool: "ssacli", ReadFailed: true})
	if !hasInsightMsg(rf, "INFO", "UNVERIFIED") {
		t.Error("unparseable output must INFO as unverified")
	}
}

// TestCheckHWRaid_BBUStatusUnreadable is the regression test for
// internal-collectors-16-02: a BBU/CacheVault entry present but with its
// state field unreadable (schema drift) must be disclosed as unverified,
// not silently treated as "no battery-backed cache fitted."
func TestCheckHWRaid_BBUStatusUnreadable(t *testing.T) {
	t.Parallel()
	unreadable := models.HWRaidInfo{Available: true, Tool: "storcli", Controllers: []models.HWRaidController{{
		ID: 0, Model: "MegaRAID 9560",
		VirtualDrives:       []models.HWRaidVD{{Name: "data", State: "Optimal"}},
		BBUStatusUnreadable: true,
	}}}
	got := checkHWRaid(unreadable)
	if !hasInsightMsg(got, "INFO", "could not be read") {
		t.Errorf("expected an unverified BBU disclosure, got %+v", got)
	}
}
