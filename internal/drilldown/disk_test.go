package drilldown

import "testing"

func TestParseDuSize_Ordering(t *testing.T) {
	// du -h units are 1024-based; cross-unit comparisons must order correctly.
	// 1023M < 1G < 2G < 1T, and 900K < 1M.
	ordered := []string{"512K", "900K", "1M", "1023M", "1G", "2G", "1T"}
	for i := 1; i < len(ordered); i++ {
		lo, hi := parseDuSize(ordered[i-1]), parseDuSize(ordered[i])
		if lo >= hi {
			t.Errorf("parseDuSize(%q)=%d should be < parseDuSize(%q)=%d", ordered[i-1], lo, ordered[i], hi)
		}
	}
	// 1G must be 1024^3 bytes.
	if got := parseDuSize("1G"); got != 1024*1024*1024 {
		t.Errorf("parseDuSize(1G) = %d, want %d", got, 1024*1024*1024)
	}
}
