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
