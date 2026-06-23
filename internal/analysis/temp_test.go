package analysis

import "testing"

// Guards the shared temperature-plausibility helpers that every temp-surfacing
// collector (GPU/NVMe/SATA/hardware) routes through. Pins the exact bounds so a
// refactor can't silently widen them and reintroduce the implausible-temp /
// 0-Kelvin sentinel false-OK/false-CRIT class on any surface.
func TestTempPlausible(t *testing.T) {
	cases := []struct {
		name    string
		c       float64
		ceiling float64
		want    bool
	}{
		{"room temp, nvme ceiling", 35, TempCeilNVMe, true},
		{"room temp, silicon ceiling", 35, TempCeilSilicon, true},
		{"floor boundary -40 is plausible", -40, TempCeilSilicon, true},
		{"nvme ceiling boundary 125", 125, TempCeilNVMe, true},
		{"silicon ceiling boundary 150", 150, TempCeilSilicon, true},
		{"just below floor -41", -41, TempCeilSilicon, false},
		{"0-Kelvin sentinel -273", -273, TempCeilSilicon, false},
		{"VMware garbage 11758", 11758, TempCeilSilicon, false},
		{"above nvme ceiling 130 (real-ish but out of nvme range)", 130, TempCeilNVMe, false},
		{"130 within silicon ceiling", 130, TempCeilSilicon, true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := TempPlausible(c.c, c.ceiling); got != c.want {
				t.Errorf("TempPlausible(%g, %g) = %v, want %v", c.c, c.ceiling, got, c.want)
			}
		})
	}
}

func TestTempNotReported(t *testing.T) {
	cases := []struct {
		c    float64
		want bool
	}{
		{-273, true},    // exact 0-Kelvin sentinel
		{-273.15, true}, // absolute zero
		{-274, true},
		{-272, false}, // a hair above the sentinel is a (cold, implausible but not "unreported") reading
		{0, false},
		{35, false},
	}
	for _, c := range cases {
		if got := TempNotReported(c.c); got != c.want {
			t.Errorf("TempNotReported(%g) = %v, want %v", c.c, got, c.want)
		}
	}
}

// Ceilings must stay distinct and ordered — silicon survives hotter than a drive.
func TestTempCeilingsOrdered(t *testing.T) {
	if !(TempCeilNVMe < TempCeilSilicon) {
		t.Fatalf("expected TempCeilNVMe (%g) < TempCeilSilicon (%g)", TempCeilNVMe, TempCeilSilicon)
	}
}
