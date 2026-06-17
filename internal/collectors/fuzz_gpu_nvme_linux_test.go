//go:build linux

package collectors

import (
	"math"
	"testing"
)

// Batch 2 of the parser-fuzzing pass: GPU/NVMe/snapper numeric parsers whose
// output feeds a verdict or a size/temperature display. Same invariants — no
// panic, no NaN/Inf, and non-negative where the value is a count/size/clock.

// FuzzParseNVMeTemp: feeds the NVMe temperature verdict. Temperatures may be
// negative (cold), but must never be NaN/Inf — that would corrupt a `temp >= N`
// comparison (NaN→false→false-OK, Inf→false CRIT).
func FuzzParseNVMeTemp(f *testing.F) {
	f.Add("308 (308 K)")
	f.Add("35 C")
	f.Add("(NaN K)")
	f.Add("1e400")
	f.Add("nan")     // ParseFloat("nan") = NaN with NO error — the fallback crasher
	f.Add("inf")     // likewise +Inf
	f.Add("(inf K)") // Inf via the Kelvin path (k>0 is true for +Inf)
	f.Fuzz(func(t *testing.T, s string) {
		c := parseNVMeTemp(s)
		if math.IsNaN(c) || math.IsInf(c, 0) {
			t.Fatalf("parseNVMeTemp(%q) = %v (want a finite number)", s, c)
		}
	})
}

// FuzzParseDPMSclk: GPU clock MHz (current/max). Negative clocks are nonsensical
// and would skew the clock display/verdict.
func FuzzParseDPMSclk(f *testing.F) {
	f.Add("0: 300Mhz\n1: 1200Mhz *")
	f.Add("500Mhz *")
	f.Add("-5Mhz *")
	f.Fuzz(func(t *testing.T, data string) {
		cur, max := parseDPMSclk(data)
		if cur < 0 || max < 0 {
			t.Fatalf("parseDPMSclk(%q) = cur=%d max=%d (want non-negative)", data, cur, max)
		}
	})
}

// FuzzParseMiB: a snapshot size in MiB. Must be finite and non-negative.
func FuzzParseMiB(f *testing.F) {
	f.Add("128 MiB")
	f.Add("4.5GiB")
	f.Add("NaNMiB")
	f.Add("-5MiB")
	f.Add("1e400GiB")
	f.Fuzz(func(t *testing.T, s string) {
		v := parseMiB(s)
		if math.IsNaN(v) || math.IsInf(v, 0) || v < 0 {
			t.Fatalf("parseMiB(%q) = %v (want finite, non-negative)", s, v)
		}
	})
}

// FuzzParseNvidiaSMILine: a nvidia-smi CSV row → GPUDevice. Must not panic on a
// malformed row.
func FuzzParseNvidiaSMILine(f *testing.F) {
	f.Add("0, NVIDIA A100, 45, 100, 30, 40000, 80000, 250")
	f.Add(",,,,,,,")
	f.Add("x")
	f.Fuzz(func(t *testing.T, line string) {
		_, _, _ = parseNvidiaSMILine(line) // must not panic
	})
}
