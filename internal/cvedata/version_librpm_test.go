package cvedata

import "testing"

// TestRpmvercmpLibrpmVectors pins this pure-Go rpmvercmp against the AUTHORITATIVE
// answers from real librpm (fedora python3-rpm `rpm.labelCompare`). rpmvercmp decides
// whether an installed package is at/below a CVE's FixedIn version (vulnerable) or
// above it (patched) — a disagreement with librpm here is a wrong CVE-exposure verdict.
// Regenerate the oracle: python3 -c 'import rpm; print(rpm.labelCompare(("0",a,""),("0",b,"")))'
func TestRpmvercmpLibrpmVectors(t *testing.T) {
	cases := []struct {
		a, b string
		want int
	}{
		{"1.0", "1.0", 0},
		{"1.0", "2.0", -1},
		{"2.0.1", "2.0.1", 0},
		{"2.0", "2.0.1", -1},
		{"2.0.1a", "2.0.1", 1},
		{"2.0.1", "2.0.1a", -1},
		{"5.5p1", "5.5p2", -1},
		{"5.5p10", "5.5p10", 0},
		{"5.5p1", "5.5p10", -1},
		{"5.5p10", "5.5p1", 1},
		{"10xyz", "10.1xyz", -1},
		{"xyz10", "xyz10.1", -1},
		{"xyz.4", "8", -1},
		{"8", "xyz.4", 1},
		{"xyz.4", "2", -1},
		{"5.5p2", "5.6p1", -1},
		{"5.6p1", "6.5p1", -1},
		{"6.0.rc1", "6.0", 1},
		{"10b2", "10a1", 1},
		{"10a2", "10b2", -1},
		{"1.0aa", "1.0a", 1},
		{"1.0a", "1.0aa", -1},
		{"10.0001", "10.0001", 0},
		{"10.0001", "10.1", 0},
		{"10.0001", "10.0039", -1},
		{"4.999.9", "5.0", -1},
		{"20101121", "20101122", -1},
		{"2_0", "2.0", 0},
		{"2.0", "2_0", 0},
		{"1.0~rc1", "1.0", -1},
		{"1.0~rc1", "1.0~rc2", -1},
		{"1.0~rc1~git123", "1.0~rc1", -1},
		{"1.0^", "1.0", 1},
		{"1.0^git1", "1.0", 1},
		{"1.0^git1", "1.0^git2", -1},
		{"1.0^git1", "1.01", -1},
		{"1.0^20160101", "1.0.1", -1},
		{"1.0^20160101^git1", "1.0^20160102", -1},
		{"1.0~rc1^git1", "1.0~rc1", 1},
		{"1.0^git1~pre", "1.0^git1", -1},
	}
	for _, c := range cases {
		if got := rpmvercmp(c.a, c.b); got != c.want {
			t.Errorf("rpmvercmp(%q, %q) = %d, want %d (librpm)", c.a, c.b, got, c.want)
		}
	}
}
