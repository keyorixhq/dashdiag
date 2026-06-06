package analysis

import "testing"

// TestApplyPolicy_AllThresholdFieldsPropagate sets every PolicyFile threshold
// field to a distinct sentinel and verifies it lands on the correct Thresholds
// field. This covers all of ApplyPolicy's override branches and guards against
// the silent-no-op bug where a new policy field is added but never wired into
// ApplyPolicy (the audit confirmed only "Deny" is intentionally unhandled).
func TestApplyPolicy_AllThresholdFieldsPropagate(t *testing.T) {
	p := &PolicyFile{
		RAMWarnPct:            71,
		RAMCritPct:            92,
		SlabWarnPct:           25,
		CPULoadWarnMultiplier: 1.5,
		CPULoadCritMultiplier: 2.5,
		DiskWarnPct:           81,
		DiskCritPct:           91,
		SwapWarnPct:           21,
		SwapCritPct:           61,
		SwapActivityWarn:      5,
		SwapActivityCrit:      999,
		IOAwaitWarnMs:         6,
		IOAwaitCritMs:         22,
		IOUtilWarnPct:         62,
		IOUtilCritPct:         86,
		NTPOffsetWarnMs:       101,
		NTPOffsetCritMs:       501,
		FDSystemWarnPct:       82,
		FDSystemCritPct:       93,
		ZombieWarnCount:       7,
		HungDStateCrit:        4,
	}

	got := ApplyPolicy(Thresholds{}, p)

	checks := []struct {
		name string
		got  float64
		want float64
	}{
		{"RAMWarnPct", got.RAMWarnPct, 71},
		{"RAMCritPct", got.RAMCritPct, 92},
		{"SlabWarnPct", got.SlabWarnPct, 25},
		{"CPULoadWarnMultiplier", got.CPULoadWarnMultiplier, 1.5},
		{"CPULoadCritMultiplier", got.CPULoadCritMultiplier, 2.5},
		{"DiskWarnPct", got.DiskWarnPct, 81},
		{"DiskCritPct", got.DiskCritPct, 91},
		{"SwapWarnPct", got.SwapWarnPct, 21},
		{"SwapCritPct", got.SwapCritPct, 61},
		{"SwapActivityWarn", got.SwapActivityWarn, 5},
		{"SwapActivityCrit", got.SwapActivityCrit, 999},
		{"IOAwaitWarnMsSSD", got.IOAwaitWarnMsSSD, 6},  // IOAwaitWarnMs -> *SSD
		{"IOAwaitCritMsSSD", got.IOAwaitCritMsSSD, 22}, // IOAwaitCritMs -> *SSD
		{"IOUtilWarnPctSSD", got.IOUtilWarnPctSSD, 62}, // IOUtilWarnPct -> *SSD
		{"IOUtilCritPctSSD", got.IOUtilCritPctSSD, 86}, // IOUtilCritPct -> *SSD
		{"NTPOffsetWarnMs", got.NTPOffsetWarnMs, 101},
		{"NTPOffsetCritMs", got.NTPOffsetCritMs, 501},
		{"FDSystemWarnPct", got.FDSystemWarnPct, 82},
		{"FDSystemCritPct", got.FDSystemCritPct, 93},
	}
	for _, c := range checks {
		if c.got != c.want {
			t.Errorf("%s = %v, want %v (policy field not wired through ApplyPolicy?)", c.name, c.got, c.want)
		}
	}
	if got.ZombieWarnCount != 7 {
		t.Errorf("ZombieWarnCount = %d, want 7", got.ZombieWarnCount)
	}
	if got.HungDStateCrit != 4 {
		t.Errorf("HungDStateCrit = %d, want 4", got.HungDStateCrit)
	}
}
