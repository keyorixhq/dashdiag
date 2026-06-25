package analysis

import (
	"testing"

	"github.com/keyorixhq/dashdiag/internal/models"
)

// TestSwapInUse covers the gate for the general-server swappiness check: swappiness
// only matters when swap exists AND is being used/paged.
func TestSwapInUse(t *testing.T) {
	cases := []struct {
		name string
		s    models.SwapInfo
		want bool
	}{
		{"no swap configured", models.SwapInfo{TotalGB: 0}, false},
		{"swap present but idle (0 used, 0 paging)", models.SwapInfo{TotalGB: 8}, false},
		{"swap in use", models.SwapInfo{TotalGB: 8, UsedPct: 12}, true},
		{"actively paging in", models.SwapInfo{TotalGB: 8, PagesInPerSec: 50}, true},
		{"actively paging out", models.SwapInfo{TotalGB: 8, PagesOutPerSec: 50}, true},
		// Guard: paging reported but no swap device → not meaningful.
		{"paging without swap device", models.SwapInfo{TotalGB: 0, PagesInPerSec: 50}, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := swapInUse(tc.s); got != tc.want {
				t.Errorf("swapInUse(%+v) = %v, want %v", tc.s, got, tc.want)
			}
		})
	}
}
