//go:build linux

package collectors

import "testing"

func TestParseCPURangeCount(t *testing.T) {
	cases := []struct {
		in   string
		want int
	}{
		{"0-13", 14},   // the live VMware hot-add case
		{"0-1", 2},     // a normal 2-vCPU guest
		{"0", 1},       // single CPU
		{"0-1,4-5", 4}, // sparse ranges
		{"2-127", 126}, // the "offline" range can be large
		{"", 0},        // unread → 0
		{"\n", 0},      // whitespace only
		{"garbage", 0}, // non-numeric → 0
	}
	for _, c := range cases {
		if got := parseCPURangeCount(c.in); got != c.want {
			t.Errorf("parseCPURangeCount(%q) = %d, want %d", c.in, got, c.want)
		}
	}
}

func TestCmdlineHasCPUIsolation(t *testing.T) {
	yes := []string{
		"BOOT_IMAGE=/vmlinuz isolcpus=2,3 ro quiet",
		"BOOT_IMAGE=/vmlinuz nohz_full=4-7 ro",
	}
	for _, c := range yes {
		if !cmdlineHasCPUIsolation(c) {
			t.Errorf("cmdlineHasCPUIsolation(%q) = false, want true", c)
		}
	}
	no := []string{
		"BOOT_IMAGE=/vmlinuz ro quiet splash",
		"",
	}
	for _, c := range no {
		if cmdlineHasCPUIsolation(c) {
			t.Errorf("cmdlineHasCPUIsolation(%q) = true, want false", c)
		}
	}
}
