//go:build linux

package collectors

import "math"

// clampMul returns n*mult for non-negative inputs, saturating to math.MaxInt on
// overflow instead of wrapping negative. Used by the duration parsers: a garbled
// huge duration should read as "very large" (and trip any upper-bound threshold),
// never as a negative value that reads as "well under the limit". A negative or
// zero operand yields 0 (a negative duration is garbage, not a real value).
func clampMul(n, mult int) int {
	if n <= 0 || mult <= 0 {
		return 0
	}
	if n > math.MaxInt/mult {
		return math.MaxInt
	}
	return n * mult
}

// clampAdd returns a+b for non-negative inputs, saturating to math.MaxInt on
// overflow.
func clampAdd(a, b int) int {
	if a < 0 || b < 0 {
		return 0
	}
	if a > math.MaxInt-b {
		return math.MaxInt
	}
	return a + b
}
