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

func TestParseNvidiaSMILineFaulted(t *testing.T) {
	// A GPU that has fallen off the bus: nvidia-smi still lists index/name/driver but
	// reports [N/A] for every metric. Previously these coerced to 0 and the device
	// read as a healthy 0°C/0% GPU (false-OK). Now it must be flagged Unreadable.
	line := "1, NVIDIA GeForce RTX 3070, [N/A], [N/A], [N/A], [N/A], [N/A], 535.183.01, [N/A]"
	dev, _, err := parseNvidiaSMILine(line)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !dev.Unreadable {
		t.Errorf("expected Unreadable=true for an all-[N/A] (fallen-off-bus) GPU")
	}
	if dev.Name != "NVIDIA GeForce RTX 3070" {
		t.Errorf("name still expected from a faulted line, got %q", dev.Name)
	}
}

func TestParseNvidiaSMILineErrField(t *testing.T) {
	// nvidia-smi can also emit "ERR!" for a faulted field.
	line := "0, Tesla V100, ERR!, ERR!, ERR!, ERR!, ERR!, 470.82, [N/A]"
	dev, _, err := parseNvidiaSMILine(line)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !dev.Unreadable {
		t.Errorf("expected Unreadable=true for an ERR! line")
	}
}

func TestParseNvidiaSMILineMIGPartialNA(t *testing.T) {
	// A healthy MIG/vGPU instance can legitimately report [N/A] for utilization
	// alone while temperature and total memory are present. Gating Unreadable on
	// BOTH temp and memTotal being unreadable must NOT false-flag this case.
	line := "0, NVIDIA A100-SXM4-40GB, 38, [N/A], 0, 40960, 65.0, 535.183.01, 400.0"
	dev, _, err := parseNvidiaSMILine(line)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if dev.Unreadable {
		t.Errorf("MIG instance with only util [N/A] must NOT be Unreadable")
	}
	if dev.TempC != 38 || dev.MemTotalMB != 40960 {
		t.Errorf("temp/memTotal = %d/%d, want 38/40960", dev.TempC, dev.MemTotalMB)
	}
}

func TestParseNvidiaSMILineHealthyNotUnreadable(t *testing.T) {
	line := "0, NVIDIA GeForce RTX 3070, 71, 100, 6823, 8192, 220.5, 535.183.01, 220.0"
	dev, _, err := parseNvidiaSMILine(line)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if dev.Unreadable {
		t.Errorf("a healthy GPU line must not be flagged Unreadable")
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
