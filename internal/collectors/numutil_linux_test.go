//go:build linux

package collectors

import (
	"math"
	"testing"
)

// TestClampAdd covers the saturating-add boundary directly: a negative
// operand collapses to 0 (a negative duration component is garbage, never a
// real value — same contract as clampMul), and a+b that would overflow
// math.MaxInt saturates instead of wrapping negative, which would otherwise
// misread a huge garbled duration as "well under the limit".
func TestClampAdd(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name string
		a, b int
		want int
	}{
		{"normal addition", 3, 4, 7},
		{"zero plus zero", 0, 0, 0},
		{"negative a collapses to 0", -1, 5, 0},
		{"negative b collapses to 0", 5, -1, 0},
		{"both negative collapses to 0", -3, -4, 0},
		{"exactly at MaxInt boundary — no saturation", math.MaxInt - 1, 1, math.MaxInt},
		{"one past MaxInt boundary — saturates", math.MaxInt - 1, 2, math.MaxInt},
		{"large overflow saturates instead of wrapping negative", math.MaxInt, math.MaxInt, math.MaxInt},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			t.Parallel()
			if got := clampAdd(c.a, c.b); got != c.want {
				t.Errorf("clampAdd(%d, %d) = %d, want %d", c.a, c.b, got, c.want)
			}
		})
	}
}
