package analysis

import (
	"strings"
	"testing"

	"github.com/keyorixhq/dashdiag/internal/models"
)

// TestCheckIO_MultipleSaturatedDrives covers the saturatedCount >= 3 branch in
// checkIO (lines 293-304): when 3 or more drives simultaneously hit 100%
// utilization a shared-component-fault WARN is emitted to point at the HBA/backplane.
func TestCheckIO_MultipleSaturatedDrives(t *testing.T) {
	t.Parallel()
	// Three SSDs each at 100% utilization triggers the shared-component hint.
	// DriveType "" falls through to the SSD path (warn=60, crit=85), so 100%
	// fires the util insight and increments saturatedCount.
	io := models.IOInfo{
		Devices: []models.IODeviceInfo{
			{Name: "sda", UtilPct: 100, DriveType: ""},
			{Name: "sdb", UtilPct: 100, DriveType: ""},
			{Name: "sdc", UtilPct: 100, DriveType: ""},
		},
	}
	got := checkIO(io, defaultThresh)
	found := false
	for _, ins := range got {
		if ins.Level == "WARN" && strings.Contains(ins.Message, "simultaneously") {
			found = true
		}
	}
	if !found {
		t.Errorf("3 saturated drives must emit a shared-component-fault WARN, got %+v", got)
	}
}

// TestCheckIO_TwoDrivesNoSharedHint verifies that exactly 2 saturated drives do NOT
// trigger the shared-component hint (threshold is >= 3).
func TestCheckIO_TwoDrivesNoSharedHint(t *testing.T) {
	t.Parallel()
	io := models.IOInfo{
		Devices: []models.IODeviceInfo{
			{Name: "sda", UtilPct: 100, DriveType: ""},
			{Name: "sdb", UtilPct: 100, DriveType: ""},
		},
	}
	got := checkIO(io, defaultThresh)
	for _, ins := range got {
		if strings.Contains(ins.Message, "simultaneously") {
			t.Errorf("2 saturated drives must not trigger the shared-component hint, got %q", ins.Message)
		}
	}
}

// TestCheckHealthDeep_CgroupNonNil covers the d.Cgroup != nil branch in
// checkHealthDeep (lines 361-363): passing a non-nil *CgroupV2Info causes
// checkCgroupV2 to be called. An empty (but non-nil) struct must not panic and
// may return zero or more insights.
func TestCheckHealthDeep_CgroupNonNil(t *testing.T) {
	t.Parallel()
	d := models.HealthDeepInfo{
		Cgroup: &models.CgroupV2Info{Available: true},
	}
	// Must not panic.
	got := checkHealthDeep(d)
	_ = got
}

// TestCheckHealthDeep_CgroupNil verifies that a nil Cgroup pointer suppresses
// the cgroup branch entirely (no panic, no cgroup insights).
func TestCheckHealthDeep_CgroupNil(t *testing.T) {
	t.Parallel()
	d := models.HealthDeepInfo{Cgroup: nil}
	got := checkHealthDeep(d)
	for _, ins := range got {
		if ins.Check == "Cgroup" {
			t.Errorf("nil Cgroup must not produce any cgroup insights, got %q", ins.Message)
		}
	}
}
