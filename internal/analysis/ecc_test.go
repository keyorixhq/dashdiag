package analysis

import (
	"testing"

	"github.com/keyorixhq/dashdiag/internal/models"
	"github.com/keyorixhq/dashdiag/internal/platform"
)

// ECC memory errors must surface in the fast health Memory check (previously
// only `dsd hardware` saw them — a failing DIMM went unseen by routine health).
func TestCheckMemory_ECC(t *testing.T) {
	var noCtr platform.ContainerContext
	cases := []struct {
		name string
		mem  models.MemoryInfo
		want string
	}{
		{"uncorrected ECC -> CRIT", models.MemoryInfo{EDACAvailable: true, UncorrectedErrors: 1}, "CRIT"},
		{"many corrected ECC -> WARN", models.MemoryInfo{EDACAvailable: true, CorrectedErrors: 500}, "WARN"},
		{"few corrected ECC -> none", models.MemoryInfo{EDACAvailable: true, CorrectedErrors: 50}, ""},
		{"EDAC unavailable -> none (gated)", models.MemoryInfo{EDACAvailable: false, UncorrectedErrors: 999}, ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assertLevel(t, checkMemory(tc.mem, defaultThresh, noCtr), tc.want)
		})
	}
}

// eccInsights is shared by the health and hardware paths; the check name varies
// but thresholds/wording must be identical.
func TestECCInsights(t *testing.T) {
	if got := eccInsights(0, 0, "Memory"); got != nil {
		t.Errorf("clean ECC should yield no insights, got %v", got)
	}
	crit := eccInsights(5, 3, "Memory") // uncorrected outranks corrected
	if len(crit) != 1 || crit[0].Level != "CRIT" || crit[0].Check != "Memory" {
		t.Errorf("uncorrected -> %+v, want one CRIT on Memory", crit)
	}
	warn := eccInsights(101, 0, "Hardware")
	if len(warn) != 1 || warn[0].Level != "WARN" || warn[0].Check != "Hardware" {
		t.Errorf("corrected>100 -> %+v, want one WARN on Hardware", warn)
	}
}
