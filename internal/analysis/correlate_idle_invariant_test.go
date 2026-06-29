package analysis

import (
	"testing"

	"github.com/keyorixhq/dashdiag/internal/models"
)

// Correlations fire only when multiple problem signals ALIGN — so on a healthy/idle
// host with no WARN/CRIT signals, NONE should fire. A rule that fires on empty/idle
// input is a false correlation (the failure mode behind #583, where an idle-but-high-
// await disk triggered a "failing drive" CRIT). This is the baseline invariant across
// both correlation entry points; the per-rule plausibility EDGES (e.g. the IO util
// floor) are pinned in their own tests — this catches a future rule that fires on no
// signal at all.
func TestCorrelate_NoFireOnIdleInput(t *testing.T) {
	if c := Correlate(nil); len(c) != 0 {
		t.Errorf("Correlate(nil) fired %d correlations on no input: %+v", len(c), c)
	}
	if c := Correlate([]models.Insight{}); len(c) != 0 {
		t.Errorf("Correlate(empty) fired %d", len(c))
	}
	// All-OK insights (no WARN/CRIT) must not align into any correlation.
	allOK := []models.Insight{
		{Check: "Memory", Level: "OK"}, {Check: "IO", Level: "OK"},
		{Check: "CPU Load", Level: "OK"}, {Check: "Network", Level: "OK"},
	}
	if c := Correlate(allOK); len(c) != 0 {
		t.Errorf("Correlate(all-OK) fired %d: %+v", len(c), c)
	}
	// Deep rules on idle/zero-value models (no OOM kills, no docker issues, no IO
	// devices, no sysctl drift) must not fire.
	deep := CorrelateDeep(nil, &models.OOMInfo{}, &models.DockerInfo{}, &models.IOInfo{}, &models.SysctlInfo{})
	if len(deep) != 0 {
		t.Errorf("CorrelateDeep(idle) fired %d: %+v", len(deep), deep)
	}
}
