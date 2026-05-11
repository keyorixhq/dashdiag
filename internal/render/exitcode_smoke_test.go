package render

import (
	"os"
	"testing"

	"github.com/keyorixhq/dashdiag/internal/models"
	"github.com/keyorixhq/dashdiag/internal/output"
)

func TestExitCodeFromInsights(t *testing.T) {
	cases := []struct {
		name     string
		insights []models.Insight
		want     int
	}{
		{"empty", nil, 0},
		{"info only", []models.Insight{{Level: "INFO", Check: "x"}}, 0},
		{"warn", []models.Insight{{Level: "WARN", Check: "IO", Message: "high await"}}, 1},
		{"crit", []models.Insight{{Level: "CRIT", Check: "Disk", Message: "full"}}, 2},
		{"warn and crit", []models.Insight{
			{Level: "WARN", Check: "IO"},
			{Level: "CRIT", Check: "Disk"},
		}, 2},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := exitCodeFromInsights(tc.insights)
			if got != tc.want {
				t.Errorf("exitCodeFromInsights: got %d, want %d", got, tc.want)
			}
		})
	}
}

func TestPrintSummaryExitCode(t *testing.T) {
	modes := []output.OutputMode{output.ModeHuman, output.ModePlain, output.ModeJSON}
	modeNames := []string{"Human", "Plain", "JSON"}

	warnInsights := []models.Insight{{Level: "WARN", Check: "IO", Message: "high await"}}
	critInsights := []models.Insight{{Level: "CRIT", Check: "Disk", Message: "full"}}

	// Redirect stdout to suppress output during test
	old := os.Stdout
	devnull, _ := os.OpenFile(os.DevNull, os.O_WRONLY, 0)
	defer func() { os.Stdout = old; devnull.Close() }()

	for i, mode := range modes {
		r := NewRenderer(mode)
		os.Stdout = devnull

		if got := r.PrintSummary(warnInsights, 0); got != 1 {
			os.Stdout = old
			t.Errorf("mode %s WARN: PrintSummary returned %d, want 1", modeNames[i], got)
		}
		if got := r.PrintSummary(critInsights, 0); got != 2 {
			os.Stdout = old
			t.Errorf("mode %s CRIT: PrintSummary returned %d, want 2", modeNames[i], got)
		}
		if got := r.PrintSummary(nil, 0); got != 0 {
			os.Stdout = old
			t.Errorf("mode %s empty: PrintSummary returned %d, want 0", modeNames[i], got)
		}
	}
	os.Stdout = old
}
