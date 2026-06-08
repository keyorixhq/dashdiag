package cvedata

import (
	"strconv"
	"strings"
)

// compareEVR compares two RPM EVR strings (epoch:version-release). It returns
// -1 if a is older than b, 0 if equal, +1 if newer — implementing RPM's
// epoch→version→release precedence with a pure-Go rpmvercmp (no CGO).
//
// This replaced a lexicographic string compare that got the common case wrong:
// "3.0.9" < "3.0.10" is FALSE lexically ('9' > '1'), so a host on the older,
// vulnerable 3.0.9 was reported as safe.
func compareEVR(a, b string) int {
	ea, va, ra := splitEVR(a)
	eb, vb, rb := splitEVR(b)
	if c := compareEpoch(ea, eb); c != 0 {
		return c
	}
	if c := rpmvercmp(va, vb); c != 0 {
		return c
	}
	return rpmvercmp(ra, rb)
}

// splitEVR splits "epoch:version-release" into its parts. A missing epoch
// defaults to "0"; a missing release to "". The epoch is the text before the
// first ':' and the release the text after the LAST '-' (RPM versions never
// contain '-', so the last '-' is unambiguous).
func splitEVR(evr string) (epoch, version, release string) {
	epoch = "0"
	if i := strings.IndexByte(evr, ':'); i >= 0 {
		epoch = evr[:i]
		evr = evr[i+1:]
	}
	if i := strings.LastIndexByte(evr, '-'); i >= 0 {
		version = evr[:i]
		release = evr[i+1:]
	} else {
		version = evr
	}
	return epoch, version, release
}

func compareEpoch(a, b string) int {
	ea := parseEpoch(a)
	eb := parseEpoch(b)
	switch {
	case ea < eb:
		return -1
	case ea > eb:
		return 1
	default:
		return 0
	}
}

// parseEpoch treats a missing / "(none)" / unparseable epoch as 0.
func parseEpoch(s string) int {
	n, err := strconv.Atoi(strings.TrimSpace(s))
	if err != nil {
		return 0
	}
	return n
}

// rpmvercmp is a pure-Go port of librpm's rpmvercmp. It segments each string
// into maximal digit and alpha runs (treating other characters as separators),
// compares segment by segment — numeric segments numerically (leading zeros
// stripped, longer wins), a numeric segment outranks an alpha one — and honours
// the '~' (sorts before everything, for pre-releases) and '^' (sorts after the
// base version) separators.
func rpmvercmp(a, b string) int {
	if a == b {
		return 0
	}
	i, j := 0, 0
	for i < len(a) || j < len(b) {
		// Skip separators, but preserve '~' and '^'.
		for i < len(a) && !isAlnum(a[i]) && a[i] != '~' && a[i] != '^' {
			i++
		}
		for j < len(b) && !isAlnum(b[j]) && b[j] != '~' && b[j] != '^' {
			j++
		}

		// Tilde sorts before everything else.
		aTilde := i < len(a) && a[i] == '~'
		bTilde := j < len(b) && b[j] == '~'
		if aTilde || bTilde {
			if !aTilde {
				return 1
			}
			if !bTilde {
				return -1
			}
			i++
			j++
			continue
		}

		// Caret: like tilde, but if one string ends the other (the base) is older.
		aCaret := i < len(a) && a[i] == '^'
		bCaret := j < len(b) && b[j] == '^'
		if aCaret || bCaret {
			if i >= len(a) {
				return -1
			}
			if j >= len(b) {
				return 1
			}
			if !aCaret {
				return 1
			}
			if !bCaret {
				return -1
			}
			i++
			j++
			continue
		}

		if i >= len(a) || j >= len(b) {
			break
		}

		// Grab the next segment (all digits or all alpha).
		startI, startJ := i, j
		isNum := isDigit(a[i])
		if isNum {
			for i < len(a) && isDigit(a[i]) {
				i++
			}
			for j < len(b) && isDigit(b[j]) {
				j++
			}
		} else {
			for i < len(a) && isAlpha(a[i]) {
				i++
			}
			for j < len(b) && isAlpha(b[j]) {
				j++
			}
		}
		segA := a[startI:i]
		segB := b[startJ:j]

		// b's segment is empty → the two are different types at this position.
		// A numeric segment outranks an alpha one.
		if len(segB) == 0 {
			if isNum {
				return 1
			}
			return -1
		}

		if isNum {
			segA = strings.TrimLeft(segA, "0")
			segB = strings.TrimLeft(segB, "0")
			if len(segA) > len(segB) {
				return 1
			}
			if len(segB) > len(segA) {
				return -1
			}
		}
		if c := strings.Compare(segA, segB); c != 0 {
			if c < 0 {
				return -1
			}
			return 1
		}
	}

	switch {
	case i >= len(a) && j >= len(b):
		return 0
	case i >= len(a):
		return -1
	default:
		return 1
	}
}

func isDigit(c byte) bool { return c >= '0' && c <= '9' }
func isAlpha(c byte) bool { return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') }
func isAlnum(c byte) bool { return isDigit(c) || isAlpha(c) }
