package render

import (
	"testing"

	"github.com/keyorixhq/dashdiag/internal/models"
)

// TestInsightForResult_CPUSubcheckEscalation guards the fix for the CPU status-row
// escalation gap: CPU sub-checks now live in the "CPU Load/" namespace so they
// escalate the "CPU Load" row (consistent with how "Memory/Slab" escalates the
// "Memory" row) — without colliding with the separate "CPU Thermal" collector.
func TestInsightForResult_CPUSubcheckEscalation(t *testing.T) {
	// A CPU Load sub-check CRIT must now attach to (escalate) the "CPU Load" row.
	got := insightForResult("CPU Load", []models.Insight{{Level: "CRIT", Check: "CPU Load/Steal", Message: "steal 25%"}})
	if got == nil || got.Level != "CRIT" {
		t.Errorf("CPU Load/Steal CRIT should escalate the CPU Load row, got %v", got)
	}

	// Sanity: the parent namespace rule still works for Memory.
	if insightForResult("Memory", []models.Insight{{Level: "WARN", Check: "Memory/Slab", Message: "slab"}}) == nil {
		t.Error("Memory/Slab should escalate the Memory row")
	}

	// Critically: the fix must NOT make the "CPU Load" row grab the separate
	// "CPU Thermal" collector's insight (the trap a naive "CPU" rename would hit).
	if got := insightForResult("CPU Load", []models.Insight{{Level: "CRIT", Check: "CPU Thermal", Message: "92C"}}); got != nil {
		t.Errorf("CPU Thermal must NOT attach to the CPU Load row, got %+v", got)
	}

	// And the worst sub-check wins when the load insight itself is only OK.
	got = insightForResult("CPU Load", []models.Insight{
		{Level: "OK", Check: "CPU Load", Message: "50%"},
		{Level: "CRIT", Check: "CPU Load/IOWait", Message: "iowait 45%"},
	})
	if got == nil || got.Level != "CRIT" {
		t.Errorf("worst CPU sub-check should win on the CPU Load row, got %v", got)
	}
}
