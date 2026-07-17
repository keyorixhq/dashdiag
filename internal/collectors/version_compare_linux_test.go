//go:build linux

package collectors

import "testing"

// TestVersionStringGreater is a regression guard for the SUSE pending-reboot
// check: a plain Go string `>` compares "...55.30-default" as LESS than
// "...55.7-default" because '3' < '7' as a character, even though 30 > 7
// numerically — so a genuinely newer service-pack kernel was judged older
// (suppressing the reboot warning) or the reverse case fired spuriously.
func TestVersionStringGreater(t *testing.T) {
	cases := []struct {
		a, b string
		want bool
	}{
		// The exact SP-update scenario: 55.30 is newer than 55.7 numerically,
		// but "55.30" < "55.7" as a plain string comparison.
		{"5.14.21-150500.55.30-default", "5.14.21-150500.55.7-default", true},
		{"5.14.21-150500.55.7-default", "5.14.21-150500.55.30-default", false},
		{"5.14.21-150500.55.7-default", "5.14.21-150500.55.7-default", false}, // equal
		{"6.4.0-150600.23.34-default", "6.4.0-150600.23.9-default", true},
		{"6.4.0-150600.23.9-default", "6.4.0-150600.23.34-default", false},
		// Major/minor version bumps still work.
		{"6.4.0-150600.1.1-default", "5.14.21-150500.55.30-default", true},
		{"5.14.21-150500.55.30-default", "6.4.0-150600.1.1-default", false},
		// Non-numeric token comparison (branch: return ta[i] > tb[i]).
		// "1beta" → ["1","beta"], "1alpha" → ["1","alpha"]: "beta" > "alpha" lexicographically.
		{"1beta", "1alpha", true},
		{"1alpha", "1beta", false},
		// Length-wins comparison (branch: return len(ta) > len(tb)).
		// Both have identical common tokens; the longer one wins.
		{"1.0.1", "1.0", true},
		{"1.0", "1.0.1", false},
	}
	for _, tc := range cases {
		if got := versionStringGreater(tc.a, tc.b); got != tc.want {
			t.Errorf("versionStringGreater(%q, %q) = %v, want %v", tc.a, tc.b, got, tc.want)
		}
	}
}
