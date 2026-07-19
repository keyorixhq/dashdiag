package cvedata

import "testing"

// TestCompareDpkgRealTool pins CompareDpkg against the AUTHORITATIVE answers from the
// real `dpkg --compare-versions` tool (debian:12). dpkg's ordering differs from rpm's
// (notably '~' before everything and letters before other punctuation), so this is
// verified against the tool, not a re-derivation. Regenerate:
//
//	dpkg --compare-versions A lt B  (exit 0 → -1) / gt B (→ 1) / else 0
func TestCompareDpkgRealTool(t *testing.T) {
	cases := []struct {
		a, b string
		want int
	}{
		{"1.0", "1.0", 0},
		{"1.0", "2.0", -1},
		{"2.0", "1.0", 1},
		{"1.0", "1.0.0", -1},
		{"1:1.0", "2.0", 1},
		{"2.0", "1:1.0", -1},
		{"0:1.0", "1.0", 0},
		{"1.0-1", "1.0-2", -1},
		{"1.0", "1.0-1", -1},
		{"1.0-1", "1.0", 1},
		{"1.0~rc1", "1.0", -1},
		{"1.0", "1.0~rc1", 1},
		{"1.0~~", "1.0~", -1},
		{"1.0~rc1", "1.0~rc2", -1},
		{"1.0a", "1.0", 1},
		{"1.0", "1.0a", -1},
		{"1.0a", "1.0+", -1},
		{"1.0+", "1.0a", 1},
		{"1.00", "1.0", 0},
		{"1.01", "1.1", 0},
		{"1.0-1~deb12u1", "1.0-1", -1},
		{"1:2.4.52-1ubuntu4.10", "1:2.4.52-1ubuntu4.9", 1},
		{"2.2.4-1ubuntu1", "2.2.4-1", 1},
		{"5.4-1", "5.4", 1},
		{"1.0~beta1", "1.0~beta1+really1.0", -1},
		{"1.0-0ubuntu1", "1.0", 1},
		{"1.0+nmu1", "1.0", 1},
		{"9.99", "10.0", -1},
		{"1.0~rc1~git1", "1.0~rc1", -1},
		{"2:1.0", "10:0.1", -1},
	}
	for _, c := range cases {
		if got := CompareDpkg(c.a, c.b); got != c.want {
			t.Errorf("CompareDpkg(%q, %q) = %d, want %d (dpkg)", c.a, c.b, got, c.want)
		}
	}
}

// TestCompareDpkg_NoneVersion tests the dpkg sentinel "(none)", emitted by
// dpkg-query for packages in config-files or half-installed state.
// "(none)" must always compare as less than any real version so it is never
// treated as "already patched" in a CVE suppression check.
func TestCompareDpkg_NoneVersion(t *testing.T) {
	cases := []struct {
		a, b string
		want int
	}{
		{"(none)", "1.0-1", -1},  // "(none)" < any real version
		{"(none)", "0.0.1", -1},  // "(none)" < even very old versions
		{"(none)", "3.0.13", -1}, // typical OVAL fixedIn version
		{"1.0-1", "(none)", 1},   // real version > "(none)"
		{"0.0.1", "(none)", 1},   // even very old real version > "(none)"
		{"(none)", "(none)", 0},  // sentinel equals itself
	}
	for _, c := range cases {
		if got := CompareDpkg(c.a, c.b); got != c.want {
			t.Errorf("CompareDpkg(%q, %q) = %d, want %d", c.a, c.b, got, c.want)
		}
	}
}
