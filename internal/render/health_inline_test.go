package render

import (
	"testing"

	"github.com/keyorixhq/dashdiag/internal/models"
)

// The inline* renderers take interface{} and type-assert to a concrete model.
// On a failed assertion they return "" with no error — so a refactor that breaks
// an assertion (or drops the value-vs-pointer branch) silently blanks a field in
// the health report. These tests guard that class of regression for a
// representative set of renderers:
//   - nil and wrong-type input must return "" (the defensive guard)
//   - valid input in BOTH value and pointer form must return non-empty

type inlineFn = func(interface{}) string

type inlineCase struct {
	fn    inlineFn
	value interface{} // valid input, value form
	ptr   interface{} // same data, pointer form
}

func inlineCases() map[string]inlineCase {
	return map[string]inlineCase{
		"CPULoad":  {inlineCPULoad, models.CPUInfo{UsagePct: 50}, &models.CPUInfo{UsagePct: 50}},
		"Memory":   {inlineMemory, models.MemoryInfo{TotalGB: 16, UsedPct: 50}, &models.MemoryInfo{TotalGB: 16, UsedPct: 50}},
		"Swap":     {inlineSwap, models.SwapInfo{TotalGB: 4, UsedGB: 1}, &models.SwapInfo{TotalGB: 4, UsedGB: 1}},
		"Entropy":  {inlineEntropy, models.EntropyInfo{Available: true, EntropyBits: 256}, &models.EntropyInfo{Available: true, EntropyBits: 256}},
		"FDLimits": {inlineFDLimits, models.FDInfo{MaxCount: 1000, OpenCount: 500, UsedPct: 50}, &models.FDInfo{MaxCount: 1000, OpenCount: 500, UsedPct: 50}},
		"OOM":      {inlineOOM, models.OOMInfo{Available: true, EventsLast24h: 3}, &models.OOMInfo{Available: true, EventsLast24h: 3}},
		"LVM":      {inlineLVM, models.LVMInfo{VGs: []models.LVMVG{{}}}, &models.LVMInfo{VGs: []models.LVMVG{{}}}},
		"Sessions": {inlineSessions, models.SessionsInfo{TotalCount: 2}, &models.SessionsInfo{TotalCount: 2}},
		"IPMI":     {inlineIPMI, models.IPMIInfo{Available: true}, &models.IPMIInfo{Available: true}},
	}
}

func TestInlineNilAndWrongTypeReturnEmpty(t *testing.T) {
	type wrong struct{ X int }
	for name, c := range inlineCases() {
		if got := c.fn(nil); got != "" {
			t.Errorf("%s(nil) = %q, want empty", name, got)
		}
		if got := c.fn(wrong{1}); got != "" {
			t.Errorf("%s(wrong-type) = %q, want empty (silent type-assertion guard)", name, got)
		}
	}
}

func TestInlineValidInputNonEmpty(t *testing.T) {
	for name, c := range inlineCases() {
		if got := c.fn(c.value); got == "" {
			t.Errorf("%s(value form) returned empty for valid input", name)
		}
		if got := c.fn(c.ptr); got == "" {
			t.Errorf("%s(pointer form) returned empty for valid input", name)
		}
	}
}

// inlineMemory does arithmetic on the populated struct — pin its exact output as
// a representative formatting regression guard.
func TestInlineMemoryFormat(t *testing.T) {
	got := inlineMemory(models.MemoryInfo{TotalGB: 16, UsedPct: 50})
	if got != "8.0/16 GB (50%)" {
		t.Errorf("inlineMemory = %q, want %q", got, "8.0/16 GB (50%)")
	}
}
