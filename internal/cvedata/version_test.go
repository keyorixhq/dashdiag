package cvedata

import "testing"

func TestRpmvercmp(t *testing.T) {
	cases := []struct {
		a, b string
		want int
	}{
		{"1.0", "1.0", 0},
		// The bug: numeric segments must compare numerically, not lexically.
		{"1.9", "1.10", -1}, // 9 < 10  (lexically "1.9" > "1.10")
		{"1.10", "1.9", 1},
		{"3.0.9", "3.0.10", -1},
		{"2.0", "10.0", -1},
		{"1.25.5", "1.9.0", 1},
		// leading zeros
		{"1.01", "1.1", 0},
		{"1.0", "1.0.1", -1}, // more segments → newer
		// numeric outranks alpha (same position)
		{"1.a", "1.0", -1},
		// a trailing extra segment is newer than the bare base (librpm semantics)
		{"1.0", "1.0a", -1},
		// alpha compare
		{"1.0a", "1.0b", -1},
		// tilde: pre-release sorts BEFORE the base
		{"1.0~rc1", "1.0", -1},
		{"1.0", "1.0~rc1", 1},
		{"1.0~rc1", "1.0~rc2", -1},
		// caret: sorts AFTER the base
		{"1.0^20240101", "1.0", 1},
		{"1.0", "1.0^20240101", -1},
		// separators are equivalent
		{"1.0.1", "1.0-1", 0},
	}
	for _, c := range cases {
		if got := rpmvercmp(c.a, c.b); got != c.want {
			t.Errorf("rpmvercmp(%q, %q) = %d, want %d", c.a, c.b, got, c.want)
		}
	}
}

func TestCompareEVR(t *testing.T) {
	cases := []struct {
		a, b string
		want int
	}{
		// epoch dominates
		{"1:1.0-1", "2:0.1-1", -1},
		{"2:1.0-1", "1:9.9-9", 1},
		{"0:1.0-1", "1.0-1", 0}, // explicit 0 epoch == implicit
		// version then release
		{"1.0-1", "1.0-2", -1},
		{"1.0-2", "1.0-1", 1},
		// the headline real-world case: openssl 3.0.9 vs fix 3.0.10
		{"0:3.0.9-1.el9", "0:3.0.10-1.el9", -1},
		// fixed-version with no release: any build of 1.10 counts as >= fix "1.10"
		{"1.10-5", "1.10", 1},
		{"1.9-5", "1.10", -1}, // older major-minor still vulnerable
	}
	for _, c := range cases {
		if got := compareEVR(c.a, c.b); got != c.want {
			t.Errorf("compareEVR(%q, %q) = %d, want %d", c.a, c.b, got, c.want)
		}
	}
}
