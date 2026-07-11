package cvedata

import "testing"

// TestParseEpoch pins the "missing / (none) / unparseable epoch defaults to
// 0" contract documented on the function.
func TestParseEpoch(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name string
		in   string
		want int
	}{
		{"plain", "3", 3},
		{"whitespace", "  7 ", 7},
		{"zero", "0", 0},
		{"empty", "", 0},
		{"none", "(none)", 0},
		{"negative", "-1", -1},
		{"garbage", "abc", 0},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			t.Parallel()
			if got := parseEpoch(c.in); got != c.want {
				t.Errorf("parseEpoch(%q) = %d, want %d", c.in, got, c.want)
			}
		})
	}
}

// TestSign covers all three branches of the tiny comparator helper. Note that
// in production sign(0) is only reachable through call sites that already
// guard against a zero argument (CompareDpkg checks ea != eb before calling,
// verrevcmp only calls it when ac != bc or firstDiff != 0) — so the x==0
// branch needs a direct unit test to be exercised at all.
func TestSign(t *testing.T) {
	t.Parallel()
	cases := []struct {
		in   int
		want int
	}{
		{-5, -1},
		{-1, -1},
		{0, 0},
		{1, 1},
		{42, 1},
	}
	for _, c := range cases {
		if got := sign(c.in); got != c.want {
			t.Errorf("sign(%d) = %d, want %d", c.in, got, c.want)
		}
	}
}

// TestDebOrder pins dpkg's order() ranking for each character class: digits
// (0, handled separately by the numeric phase), letters (byte value),
// end-of-string via '~' (-1, sorts before everything), and other punctuation
// (byte value + 256, sorts after letters).
func TestDebOrder(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name string
		in   byte
		want int
	}{
		{"digit", '5', 0},
		{"digit zero", '0', 0},
		{"lowercase letter", 'a', int('a')},
		{"uppercase letter", 'Z', int('Z')},
		{"tilde", '~', -1},
		{"punctuation plus", '+', int('+') + 256},
		{"punctuation dot", '.', int('.') + 256},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			t.Parallel()
			if got := debOrder(c.in); got != c.want {
				t.Errorf("debOrder(%q) = %d, want %d", c.in, got, c.want)
			}
		})
	}
}

// TestCompareCaret exercises the '^' handling directly (RPM's "sorts after
// the base" separator), including the end-of-string edge cases that are hard
// to hit indirectly through rpmvercmp's full-string table.
func TestCompareCaret(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name        string
		a, b        string
		i, j        int
		wantDecided bool
		wantRes     int
	}{
		{"neither has caret", "1.0", "1.0", 0, 0, false, 0},
		// realistic rpmvercmp positions: after the shared "1.0" prefix, one
		// side is exhausted and the other points at '^'.
		{"only a has caret, b exhausted", "1.0^20240101", "1.0", 3, 3, true, 1},
		{"only b has caret, a exhausted", "1.0", "1.0^20240101", 3, 3, true, -1},
		{"both caret, both continue", "^1", "^2", 0, 0, true, continueLoop},
		// neither side exhausted: a lacks caret, b has it (and vice versa).
		{"a lacks caret, b has it, neither exhausted", "5", "^5", 0, 0, true, 1},
		{"a has caret, b lacks it, neither exhausted", "^5", "5", 0, 0, true, -1},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			t.Parallel()
			i, j := c.i, c.j
			decided, res := compareCaret(c.a, c.b, &i, &j)
			if decided != c.wantDecided || res != c.wantRes {
				t.Errorf("compareCaret(%q, %q, %d, %d) = (%v, %d), want (%v, %d)",
					c.a, c.b, c.i, c.j, decided, res, c.wantDecided, c.wantRes)
			}
		})
	}
}
