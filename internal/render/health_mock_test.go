package render

import (
	"testing"

	"github.com/keyorixhq/dashdiag/internal/models"
	"github.com/keyorixhq/dashdiag/internal/output"
	"github.com/keyorixhq/dashdiag/internal/runner"
)

func TestDisplayOrder(t *testing.T) {
	t.Parallel()
	got := DisplayOrder()
	if len(got) == 0 {
		t.Fatal("DisplayOrder returned empty slice")
	}
	if got[0] != "CPU Load" {
		t.Errorf("DisplayOrder()[0] = %q, want %q", got[0], "CPU Load")
	}
	// Must be the same backing data as the internal displayOrder var.
	if len(got) != len(displayOrder) {
		t.Errorf("DisplayOrder() len = %d, want %d", len(got), len(displayOrder))
	}
}

// PrintAllMock is used by `dsd mock` — it renders fixture rows using an
// external inline func instead of real collector inline data. Cover both
// output modes and both the insight-present and OK/inline-fallback paths.
func TestPrintAllMock(t *testing.T) {
	t.Parallel()
	results := []runner.Result{
		{Name: "CPU Load", Data: models.CPUInfo{UsagePct: 10}},
		{Name: "Memory", Data: models.MemoryInfo{TotalGB: 16, UsedPct: 50}},
	}
	insights := []models.Insight{
		{
			Level: "CRIT", Check: "CPU Load", Message: "95% CPU",
			Details: &models.Details{Type: "table", Title: "t", Columns: []string{"a"}, Rows: [][]string{{"1"}}},
		},
	}
	inlineFn := func(name string) string { return "inline:" + name }

	modes := map[string]output.OutputMode{"human": output.ModeHuman, "plain": output.ModePlain}
	for name, mode := range modes {
		name, mode := name, mode
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			r := NewRenderer(mode)
			quietStdout(t, func() {
				r.PrintAllMock(results, insights, inlineFn)
			})
		})
	}
}
