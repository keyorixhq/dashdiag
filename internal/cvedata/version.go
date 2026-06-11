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
//
// The loop body is split into helpers (separator skip, tilde, caret, segment
// compare) so each piece stays individually simple; behaviour is identical to
// the single-function form and is pinned by TestRpmvercmp's edge-case table.
func rpmvercmp(a, b string) int {
	if a == b {
		return 0
	}
	i, j := 0, 0
	for i < len(a) || j < len(b) {
		skipSeparators(a, &i)
		skipSeparators(b, &j)

		if decided, res := compareTilde(a, b, &i, &j); decided {
			if res == continueLoop {
				continue
			}
			return res
		}
		if decided, res := compareCaret(a, b, &i, &j); decided {
			if res == continueLoop {
				continue
			}
			return res
		}

		if i >= len(a) || j >= len(b) {
			break
		}

		if decided, res := compareSegment(a, b, &i, &j); decided {
			return res
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

// continueLoop is a sentinel result meaning "both cursors advanced, keep looping"
// (distinct from the -1/0/1 comparison results).
const continueLoop = 2

// skipSeparators advances idx over separator bytes, preserving '~' and '^'.
func skipSeparators(s string, idx *int) {
	for *idx < len(s) && !isAlnum(s[*idx]) && s[*idx] != '~' && s[*idx] != '^' {
		*idx++
	}
}

// compareTilde handles '~' (sorts before everything else). Returns decided=true
// when it resolved the comparison or consumed a matching pair (res=continueLoop).
func compareTilde(a, b string, i, j *int) (decided bool, res int) {
	aTilde := *i < len(a) && a[*i] == '~'
	bTilde := *j < len(b) && b[*j] == '~'
	if !aTilde && !bTilde {
		return false, 0
	}
	if !aTilde {
		return true, 1
	}
	if !bTilde {
		return true, -1
	}
	*i++
	*j++
	return true, continueLoop
}

// compareCaret handles '^' (like tilde, but if one string ends, the base is older).
func compareCaret(a, b string, i, j *int) (decided bool, res int) {
	aCaret := *i < len(a) && a[*i] == '^'
	bCaret := *j < len(b) && b[*j] == '^'
	if !aCaret && !bCaret {
		return false, 0
	}
	if *i >= len(a) {
		return true, -1
	}
	if *j >= len(b) {
		return true, 1
	}
	if !aCaret {
		return true, 1
	}
	if !bCaret {
		return true, -1
	}
	*i++
	*j++
	return true, continueLoop
}

// compareSegment grabs the next maximal digit-or-alpha run from each string and
// compares them: numeric outranks alpha, numerics compare by stripped length
// then lexically. decided=false means the segments were equal — keep looping.
func compareSegment(a, b string, i, j *int) (decided bool, res int) {
	startI, startJ := *i, *j
	isNum := isDigit(a[*i])
	if isNum {
		for *i < len(a) && isDigit(a[*i]) {
			*i++
		}
		for *j < len(b) && isDigit(b[*j]) {
			*j++
		}
	} else {
		for *i < len(a) && isAlpha(a[*i]) {
			*i++
		}
		for *j < len(b) && isAlpha(b[*j]) {
			*j++
		}
	}
	segA := a[startI:*i]
	segB := b[startJ:*j]

	// b's segment is empty → different types at this position; numeric outranks alpha.
	if len(segB) == 0 {
		if isNum {
			return true, 1
		}
		return true, -1
	}

	if isNum {
		segA = strings.TrimLeft(segA, "0")
		segB = strings.TrimLeft(segB, "0")
		if len(segA) > len(segB) {
			return true, 1
		}
		if len(segB) > len(segA) {
			return true, -1
		}
	}
	if c := strings.Compare(segA, segB); c != 0 {
		if c < 0 {
			return true, -1
		}
		return true, 1
	}
	return false, 0
}

func isDigit(c byte) bool { return c >= '0' && c <= '9' }
func isAlpha(c byte) bool { return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') }
func isAlnum(c byte) bool { return isDigit(c) || isAlpha(c) }
