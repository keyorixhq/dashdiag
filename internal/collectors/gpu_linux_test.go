//go:build linux

package collectors

import "testing"

func TestParseDPMSclk(t *testing.T) {
	tests := []struct {
		name    string
		in      string
		wantCur int
		wantMax int
	}{
		{
			name:    "steam deck van gogh",
			in:      "0: 200Mhz\n1: 700Mhz\n2: 1600Mhz *",
			wantCur: 1600,
			wantMax: 1600,
		},
		{
			name:    "throttled to mid level",
			in:      "0: 200Mhz\n1: 700Mhz *\n2: 1600Mhz",
			wantCur: 700,
			wantMax: 1600,
		},
		{
			name:    "no active marker",
			in:      "0: 300Mhz\n1: 2400Mhz",
			wantCur: 0,
			wantMax: 2400,
		},
		{
			name:    "empty",
			in:      "",
			wantCur: 0,
			wantMax: 0,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			cur, max := parseDPMSclk(tc.in)
			if cur != tc.wantCur || max != tc.wantMax {
				t.Errorf("parseDPMSclk(%q) = (%d, %d), want (%d, %d)", tc.in, cur, max, tc.wantCur, tc.wantMax)
			}
		})
	}
}

func TestParseNvidiaSMILine(t *testing.T) {
	// index,name,temp,util,mem.used,mem.total,power.draw,driver_version,power.limit
	line := "0, NVIDIA GeForce RTX 3070, 71, 100, 6823, 8192, 220.5, 535.183.01, 220.0"
	dev, driver, err := parseNvidiaSMILine(line)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if driver != "535.183.01" {
		t.Errorf("driver = %q, want 535.183.01", driver)
	}
	if dev.TempC != 71 || dev.UtilPct != 100 {
		t.Errorf("temp/util = %d/%d, want 71/100", dev.TempC, dev.UtilPct)
	}
	if dev.TDPLimitW != 220.0 {
		t.Errorf("TDPLimitW = %v, want 220.0", dev.TDPLimitW)
	}
	// draw 220.5 >= 0.95*220 (=209) → throttling
	if !dev.Throttling {
		t.Errorf("expected throttling when draw >= 95%% of limit")
	}
	wantGB := 8192.0 / 1024
	if dev.VRAMTotalGB != wantGB {
		t.Errorf("VRAMTotalGB = %v, want %v", dev.VRAMTotalGB, wantGB)
	}
}

func TestParseNvidiaSMILineNoLimit(t *testing.T) {
	// Older nvidia-smi without power.limit (8 fields) must still parse and not throttle.
	line := "0, Tesla T4, 45, 10, 100, 16000, 30.0, 470.82"
	dev, _, err := parseNvidiaSMILine(line)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if dev.Throttling {
		t.Errorf("should not throttle without a known power limit")
	}
	if dev.TDPLimitW != 0 {
		t.Errorf("TDPLimitW = %v, want 0", dev.TDPLimitW)
	}
}

func TestCardIndex(t *testing.T) {
	if got := cardIndex("/sys/class/drm/card0"); got != 0 {
		t.Errorf("cardIndex(card0) = %d, want 0", got)
	}
	if got := cardIndex("/sys/class/drm/card1"); got != 1 {
		t.Errorf("cardIndex(card1) = %d, want 1", got)
	}
}
