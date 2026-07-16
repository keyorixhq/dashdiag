package cvedata

import "testing"

// FuzzCompareDpkg fuzzes the dpkg version comparator against three algebraic
// invariants that must hold for any correct total ordering:
//
//   - result ∈ {-1, 0, 1} (bounded output — no raw sign())
//   - CompareDpkg(a, a) == 0 (reflexivity)
//   - CompareDpkg(a, b) == -CompareDpkg(b, a) (antisymmetry)
//
// Seeds are drawn from the dpkg --compare-versions golden set in
// version_dpkg_test.go. Any mutation that violates an invariant is a
// correctness bug in verrevcmp or splitDebVersion.
func FuzzCompareDpkg(f *testing.F) {
	seeds := []string{
		"1.0",
		"2.0",
		"1.0.0",
		"1:1.0",
		"0:1.0",
		"1.0-1",
		"1.0-2",
		"1.0~rc1",
		"1.0~rc2",
		"1.0~~",
		"1.0a",
		"1.0+deb10u1",
		"2:5.10.0",
		"3.0.13-0ubuntu3.4",
		"",
		"0",
		"~",
		"0:0-0",
	}
	for _, s := range seeds {
		f.Add(s, s)
	}
	f.Add("1.0", "2.0")
	f.Add("1:0", "2.0")
	f.Add("1.0~rc1", "1.0")

	f.Fuzz(func(t *testing.T, a, b string) {
		ab := CompareDpkg(a, b)
		ba := CompareDpkg(b, a)

		if ab != -1 && ab != 0 && ab != 1 {
			t.Fatalf("CompareDpkg(%q, %q) = %d, want -1|0|1", a, b, ab)
		}
		if ba != -1 && ba != 0 && ba != 1 {
			t.Fatalf("CompareDpkg(%q, %q) = %d, want -1|0|1", b, a, ba)
		}
		if ab != -ba {
			t.Fatalf("antisymmetry: CompareDpkg(%q,%q)=%d but CompareDpkg(%q,%q)=%d, want %d", a, b, ab, b, a, ba, -ab)
		}
		if CompareDpkg(a, a) != 0 {
			t.Fatalf("reflexivity: CompareDpkg(%q,%q) != 0", a, a)
		}
		if CompareDpkg(b, b) != 0 {
			t.Fatalf("reflexivity: CompareDpkg(%q,%q) != 0", b, b)
		}
	})
}
