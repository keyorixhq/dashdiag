package cvedata

import "strings"

// Debian/Ubuntu version comparison. dpkg uses a DIFFERENT algorithm than RPM's
// rpmvercmp (version.go) — most notably its character ordering puts '~' before
// everything (including end-of-string, for pre-releases), then plain end-of-string,
// then digits, then letters, then other punctuation. A naive reuse of rpmvercmp
// gets cases like "1.0a" vs "1.0+" backwards. This is a faithful port of dpkg's
// verrevcmp (deb-version(7) / dpkg lib/dpkg/version.c), pinned against the real
// `dpkg --compare-versions` tool in version_dpkg_test.go.
//
// NOTE: this is a self-contained building block. It is deliberately NOT yet wired
// into the Ubuntu/Debian OVAL scan (ScanUbuntuOVALPackages), which is name-based
// today. Making that scan version-aware risks turning a safe false-positive
// (over-reporting a patched CVE) into a false-OK (suppressing a real one) if the
// OVAL fixed-version extraction is wrong — that wiring needs real Ubuntu OVAL
// fixtures to validate first. Until then this comparator stands ready and verified.

// CompareDpkg compares two Debian package versions and returns -1, 0, or 1
// (a<b, a==b, a>b). It follows dpkg semantics: epoch (numeric, default 0), then
// upstream_version, then debian_revision, the latter two via verrevcmp.
func CompareDpkg(a, b string) int {
	ea, ua, ra := splitDebVersion(a)
	eb, ub, rb := splitDebVersion(b)
	if ea != eb {
		return sign(ea - eb)
	}
	if c := verrevcmp(ua, ub); c != 0 {
		return c
	}
	return verrevcmp(ra, rb)
}

// splitDebVersion parses [epoch:]upstream[-revision]. A missing epoch is 0; a
// missing revision is "" (verrevcmp treats "" as lower than any non-empty
// revision, matching dpkg). The revision is split on the LAST '-'.
func splitDebVersion(v string) (epoch int, upstream, revision string) {
	v = strings.TrimSpace(v)
	if i := strings.IndexByte(v, ':'); i >= 0 {
		epoch = parseEpoch(v[:i])
		v = v[i+1:]
	}
	if i := strings.LastIndexByte(v, '-'); i >= 0 {
		upstream, revision = v[:i], v[i+1:]
	} else {
		upstream = v
	}
	return epoch, upstream, revision
}

// debOrder is dpkg's order(): '~' sorts before everything (returns -1, below the
// 0 that both digits and end-of-string yield); letters keep their byte value; any
// other punctuation sorts AFTER letters (value + 256). This ranking is the crux of
// the dpkg-vs-rpm difference.
func debOrder(c byte) int {
	switch {
	case c >= '0' && c <= '9':
		return 0 // digits are handled by the numeric phase; 0 here so end-of-string ties
	case (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z'):
		return int(c)
	case c == '~':
		return -1
	default:
		return int(c) + 256
	}
}

// verrevcmp ports dpkg's verrevcmp: alternate a non-digit phase (compared char by
// char via debOrder, where a cursor past the end contributes order 0) and a digit
// phase (leading zeros stripped, longer run wins, else first differing digit).
func verrevcmp(a, b string) int {
	i, j := 0, 0
	for i < len(a) || j < len(b) {
		// Non-digit phase: continue while EITHER side has a non-digit char.
		for (i < len(a) && !isDigit(a[i])) || (j < len(b) && !isDigit(b[j])) {
			ac, bc := 0, 0 // a cursor past end-of-string contributes order 0
			if i < len(a) {
				ac = debOrder(a[i])
			}
			if j < len(b) {
				bc = debOrder(b[j])
			}
			if ac != bc {
				return sign(ac - bc)
			}
			i++
			j++
		}
		// Strip leading zeros so e.g. "1.0" == "1.00".
		for i < len(a) && a[i] == '0' {
			i++
		}
		for j < len(b) && b[j] == '0' {
			j++
		}
		// Digit phase: longer remaining digit run is the larger number; on equal
		// length, the first differing digit decides.
		firstDiff := 0
		for i < len(a) && isDigit(a[i]) && j < len(b) && isDigit(b[j]) {
			if firstDiff == 0 {
				firstDiff = int(a[i]) - int(b[j])
			}
			i++
			j++
		}
		if i < len(a) && isDigit(a[i]) {
			return 1
		}
		if j < len(b) && isDigit(b[j]) {
			return -1
		}
		if firstDiff != 0 {
			return sign(firstDiff)
		}
	}
	return 0
}

func sign(x int) int {
	switch {
	case x < 0:
		return -1
	case x > 0:
		return 1
	default:
		return 0
	}
}
