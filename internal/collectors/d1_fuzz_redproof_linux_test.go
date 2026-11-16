//go:build linux

package collectors

// Red/green proofs for the two D1 fuzzers' oracles. A guard nobody has watched
// fail is not a guard: each test below plants a defect and confirms the SAME
// oracle predicate the fuzzer uses goes RED, then confirms the real,
// defect-free path stays GREEN (the silent control). Production code is NOT
// modified — the defect is injected as a local buggy parser (Fuzzer A) or as a
// deliberately inconsistent input rendering driven through the real collectors
// (Fuzzer B).

import (
	"strconv"
	"strings"
	"testing"
)

// ── Fuzzer A — O-A2 (fail-closed / no silent misparse) ───────────────────────

// buggyParseMiBStripComma is the classic #727/#862-adjacent defect: it "helpfully"
// strips commas before parsing, so a decimal-comma value like "512,5 MiB" (which
// means 512.5 in de_DE but NEVER reaches this parser under LC_ALL=C) is silently
// turned into the wrong number 5125 — a plausible-but-wrong size, not a rejection.
// The real parseMiB does NOT do this; it fails closed to 0.
func buggyParseMiBStripComma(s string) (float64, bool) {
	s = strings.TrimSpace(s)
	if !strings.HasSuffix(s, "MiB") && !strings.HasSuffix(s, "GiB") {
		return 0, true
	}
	s = strings.TrimSuffix(strings.TrimSuffix(s, "MiB"), "GiB")
	s = strings.TrimSpace(s)
	s = strings.ReplaceAll(s, ",", "") // THE BUG: comma-strip before parse
	f, err := strconv.ParseFloat(s, 64)
	if err != nil || f < 0 {
		return 0, true
	}
	return f, f == 0
}

func TestSizeNumberFormatInvariant_RedProof(t *testing.T) {
	const canonStr = "512 MiB"
	canonVal := parseMiB(canonStr) // 512
	if canonVal != 512 {
		t.Fatalf("fixture: parseMiB(%q)=%v, want 512", canonStr, canonVal)
	}
	// A decimal-comma variant of the SAME logical value — the shape de_DE would
	// render but that LC_ALL=C guarantees never reaches the parser.
	variant := "512,5 MiB"

	// RED: the buggy comma-stripping parser turns the variant into a non-sentinel
	// wrong number (5125) — O-A2 must catch it.
	if got, bad := oA2Misparse(buggyParseMiBStripComma, canonVal, variant); !bad {
		t.Fatalf("RED-PROOF FAILED: O-A2 did not flag the comma-stripping misparse of %q (got=%v) — the oracle has no teeth", variant, got)
	}

	// GREEN / silent control: the REAL parseMiB fails closed (→ 0 sentinel), so
	// O-A2 must NOT fire. If it did, the oracle would be a false-positive machine.
	realParse := func(s string) (float64, bool) { x := parseMiB(s); return x, x == 0 }
	if got, bad := oA2Misparse(realParse, canonVal, variant); bad {
		t.Fatalf("GREEN-PROOF FAILED: O-A2 fired on the real parseMiB for %q (got=%v) — false positive", variant, got)
	}
}

// ── Fuzzer B — O-B1 (cross-distro SecurityUpdates agreement) ─────────────────

// TestCrossDistroDifferential_RedProof drives the REAL collectors. GREEN: three
// consistent renderings of the same logical set agree. RED: an apt rendering that
// drops the security tag on one line (so collectAPT legitimately skips it) makes
// apt undercount vs dnf — the differential must detect the divergence.
func TestCrossDistroDifferential_RedProof(t *testing.T) {
	classes := []sevClass{sevCrit, sevImp, sevOther}

	dnf := driveCollector(t, seedDNF(renderDNF(classes)), collectDNF, "collectDNF")

	// GREEN / silent control: consistent apt rendering agrees with dnf.
	aptGreen := driveCollector(t, seedAPT(renderAPT(classes)), collectAPT, "collectAPT(green)")
	if dnf.SecurityUpdates != aptGreen.SecurityUpdates {
		t.Fatalf("GREEN-PROOF FAILED: consistent renderings disagree dnf=%d apt=%d — differential is a false-positive machine",
			dnf.SecurityUpdates, aptGreen.SecurityUpdates)
	}

	// RED: build an apt output where the LAST line lacks any security tag, so
	// collectAPT skips it (packages_linux.go:514-518) and counts one fewer than
	// dnf. The O-B1 equality must now be false.
	aptLines := strings.Split(strings.TrimRight(renderAPT(classes), "\n"), "\n")
	if len(aptLines) != len(classes) {
		t.Fatalf("fixture: expected %d apt lines, got %d", len(classes), len(aptLines))
	}
	// Strip the "-security" marker from the last line (replace the whole source
	// field with a non-security suite).
	aptLines[len(aptLines)-1] = "Inst tailpkg [1.0] (1.1 Debian:stable/main [amd64])"
	aptRedOut := strings.Join(aptLines, "\n") + "\n"
	aptRed := driveCollector(t, seedAPT(aptRedOut), collectAPT, "collectAPT(red)")

	if dnf.SecurityUpdates == aptRed.SecurityUpdates {
		t.Fatalf("RED-PROOF FAILED: differential did not catch the undercount dnf=%d apt=%d — the oracle has no teeth",
			dnf.SecurityUpdates, aptRed.SecurityUpdates)
	}
	if aptRed.SecurityUpdates != dnf.SecurityUpdates-1 {
		t.Fatalf("RED-PROOF sanity: expected apt to undercount by exactly 1 (dnf=%d apt=%d)", dnf.SecurityUpdates, aptRed.SecurityUpdates)
	}
}
