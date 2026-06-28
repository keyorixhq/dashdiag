package analysis

import (
	"strings"
	"testing"

	"github.com/keyorixhq/dashdiag/internal/models"
)

// "Errors found by the last scrub" (unrepairable data corruption) was parsed by
// the ZFS collector but never warned on — only the cumulative vdev counters and
// scrub age were checked.
func TestCheckZFSPool_ScrubErrors(t *testing.T) {
	// Scrub found unrepairable errors -> CRIT, even with clean vdev counters.
	got := checkZFSPool(models.ZFSPool{Name: "tank", State: "ONLINE", ScrubAgeDays: 5, ScrubErrors: 3})
	if !hasLevel(got, "CRIT") {
		t.Fatalf("scrub errors should produce a CRIT, got %+v", got)
	}
	found := false
	for _, ins := range got {
		if strings.Contains(ins.Message, "unrepairable") {
			found = true
		}
	}
	if !found {
		t.Errorf("want an 'unrepairable' scrub-error message, got %+v", got)
	}

	// Clean scrub -> no scrub-error insight.
	for _, ins := range checkZFSPool(models.ZFSPool{Name: "tank", State: "ONLINE", ScrubAgeDays: 5, ScrubErrors: 0}) {
		if strings.Contains(ins.Message, "unrepairable") {
			t.Errorf("clean pool must not warn scrub errors, got %+v", ins)
		}
	}
}

// A SUSPENDED pool (I/O halted, the most severe state) must be a hard CRIT — it was
// missing from the state switch and a pool can suspend before recording any error
// counter, so it previously rendered green (false-OK).
func TestCheckZFSPool_Suspended(t *testing.T) {
	got := checkZFSPool(models.ZFSPool{Name: "tank", State: "SUSPENDED"})
	found := false
	for _, ins := range got {
		if ins.Level == "CRIT" && strings.Contains(ins.Message, "SUSPENDED") {
			found = true
		}
	}
	if !found {
		t.Errorf("SUSPENDED pool must CRIT, got %+v", got)
	}
}

// checkDiskExtras must NOT score ZFS pools (the dedicated checkZFS owns them) — else
// every pool is double-scored, with a never-scrubbed verdict flip (Disk INFO vs ZFS
// WARN). A never-scrubbed pool in DiskInfo must yield no ZFS "Disk" insight here.
func TestCheckDiskExtras_NoZFSDoubleScore(t *testing.T) {
	got := checkDiskExtras(models.DiskInfo{
		ZFSPools: []models.ZFSPool{{Name: "tank", State: "ONLINE", ScrubAgeDays: -1}},
	})
	for _, ins := range got {
		if strings.Contains(ins.Message, "ZFS pool") {
			t.Errorf("checkDiskExtras must not emit ZFS insights (double-score); got %q", ins.Message)
		}
	}
}
