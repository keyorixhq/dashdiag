//go:build linux

package collectors

// FuzzSizeNumberFormatInvariant is a LOCALE/FORMAT metamorphic fuzzer for the
// size/number-parsing surface the task calls the "parseMiB / #727 class" (D1
// item 2). It operationalises the task's own classification rule — "only assert
// equality for variants the tool really emits in the wild; classify any
// divergence as a parser bug, an unsupported-format limit, or a harness artifact."
//
// CRITICAL CONTEXT (why this is not a naive de_DE-comma equality fuzzer):
// dsd pins LC_ALL=C / LANG=C on EVERY parsed subprocess at the single exec choke
// point (internal/platform/trustedexec.go:40-41, applied via
// collector.go/localeSafeExec). So every tool dsd parses emits C-locale output:
// ASCII '.' decimal point, NO thousands grouping, NO decimal comma, NO NBSP. A
// LANG=de_DE "1.234,5" rendering of a number DOES NOT REACH ANY dsd PARSER in the
// wild. Asserting "de_DE comma → same value" would therefore test an input the
// tool never produces — a HARNESS ARTIFACT by the task's taxonomy. This fuzzer
// does not do that. Instead it splits the variants into three honest buckets:
//
//   O-A1  ACCEPT-and-equal (variants that DO occur and MUST be tolerated):
//         ASCII leading/trailing whitespace, CR (CRLF line endings), and a
//         trailing NBSP — all stripped by strings.TrimSpace (unicode.IsSpace
//         covers U+00A0). The parsed value MUST equal the canonical value.
//
//   O-A2  REJECT-or-equal / FAIL-CLOSED (variants that do NOT occur under
//         LC_ALL=C — decimal comma, ASCII thousands grouping, NBSP used as an
//         internal grouping separator, ANSI SGR colour wrapping): the result MUST
//         be EITHER the canonical value OR the parser's not-measured sentinel
//         (0 / ok=false) — NEVER a THIRD, finite, wrong value. A third value is a
//         silent misparse: exactly the #727/#862 failure shape where a hostile or
//         unexpected byte sequence yields a plausible-but-wrong number that then
//         slips under an analysis ">0" threshold as a false-OK. The asymmetry is
//         intentional: over-rejection (→ sentinel) is the SAFE "honest not
//         measured" direction and is allowed; a wrong non-sentinel number is not.
//
//   O-A3  THOUSANDS-SEPARATOR EQUALITY on the one parser that really strips them
//         (smartctl NVMe value extraction, disk_linux.go:284, with its own
//         in-tree comment "strip thousand-separators e.g. 7,183"): the ASCII
//         comma-grouped rendering of a count MUST parse to the same SMARTInfo
//         field as the ungrouped rendering.
//
// What this fuzzer does NOT verify (per the task's honesty requirement):
//   - That de_DE/French-NBSP-grouped numbers are ACCEPTED — they are not emitted
//     in the wild (LC_ALL=C), and O-A2 only requires they not MISPARSE.
//   - End-to-end verdict invariance through a live collector — it asserts at the
//     parser-value layer, which is strictly stronger for a single value than a
//     verdict comparison (a value flip is necessary for a locale-driven verdict
//     flip), but does not cover cross-field interactions inside a collector. The
//     verdict-level counterpart for whitespace already ships as
//     FuzzWholeBundleReplayVerdictFlip (thermal/edac "whitespace-around-value").
//   - Over-rejection by O-A2 (a format wrongly dropped to sentinel) — that is the
//     fail-safe direction and is deliberately tolerated.

import (
	"fmt"
	"strings"
	"testing"

	"github.com/keyorixhq/dashdiag/internal/models"
)

// ── parser adapters ──────────────────────────────────────────────────────────
// Each adapter renders a canonical C-locale string for an integer value and
// parses a string back to (value, sentinel). sentinel=true ⇔ "not measured".

type sizeParser struct {
	name string
	// canonical renders value v in the exact C-locale shape the tool emits.
	canonical func(v int64) string
	// parse returns (value, sentinelMeaningNotMeasured).
	parse func(s string) (float64, bool)
	// tokenFed is true when the parser is only ever handed a strings.Fields token
	// in production (never a raw, surrounding-whitespace-bearing substring), so
	// leading/trailing whitespace CANNOT reach it in the wild. For such a parser,
	// O-A1 whitespace-acceptance is a HARNESS ARTIFACT, not a real property, and is
	// skipped (O-A2 fail-closed still applies — it is universally valid). This
	// classification was forced by the fuzzer itself: parseZFSCount (fed by the
	// vdev-error strings.Fields split, zfs.go:187-206 / disk_linux.go:458-467)
	// deliberately does not TrimSpace, and asserting it would be testing an input
	// the caller never produces.
	tokenFed bool
}

func sizeParsers() []sizeParser {
	return []sizeParser{
		{
			name:      "parseMiB",
			canonical: func(v int64) string { return fmt.Sprintf("%d MiB", v) },
			parse: func(s string) (float64, bool) {
				x := parseMiB(s)
				return x, x == 0
			},
		},
		{
			name:      "parseZFSSize", // "<n>G" → GiB; here v GiB
			canonical: func(v int64) string { return fmt.Sprintf("%dG", v) },
			parse: func(s string) (float64, bool) {
				x := parseZFSSize(s)
				return x, x == 0
			},
		},
		{
			name:      "parseZFSCount",
			canonical: func(v int64) string { return fmt.Sprintf("%d", v) },
			parse: func(s string) (float64, bool) {
				n, ok := parseZFSCount(s)
				return float64(n), !ok
			},
			tokenFed: true, // fed only strings.Fields tokens → O-A1 whitespace N/A
		},
	}
}

// ── format mutations ─────────────────────────────────────────────────────────

// groupThousands inserts ASCII commas every three digits from the right of the
// leading integer run (e.g. "1234500" → "1,234,500"), leaving a unit suffix in
// place. This is the real smartctl/drbd grouping shape.
func groupThousands(s string) string {
	// Split leading digit run from the remainder (unit / suffix).
	i := 0
	for i < len(s) && s[i] >= '0' && s[i] <= '9' {
		i++
	}
	digits, rest := s[:i], s[i:]
	if len(digits) <= 3 {
		return s
	}
	var b strings.Builder
	pre := len(digits) % 3
	if pre > 0 {
		b.WriteString(digits[:pre])
	}
	for j := pre; j < len(digits); j += 3 {
		if b.Len() > 0 {
			b.WriteByte(',')
		}
		b.WriteString(digits[j : j+3])
	}
	return b.String() + rest
}

// ansiWrap wraps the whole string in an ANSI SGR bold+reset sequence.
func ansiWrap(s string) string { return "\x1b[1m" + s + "\x1b[0m" }

// ── O-A1 / O-A2 size-parser oracles ──────────────────────────────────────────

func checkSizeParser(t *testing.T, p sizeParser, v int64) {
	canonStr := p.canonical(v)
	canonVal, canonSentinel := p.parse(canonStr)
	// Only meaningful when the canonical value is itself measured & non-sentinel;
	// v>=1 guarantees this for all three parsers.
	if canonSentinel {
		t.Fatalf("[%s] canonical %q read as not-measured — harness/fixture bug (v=%d)", p.name, canonStr, v)
	}

	// O-A1 ACCEPT-and-equal: whitespace / CR / trailing NBSP must parse to canon.
	// Skipped for token-fed parsers (whitespace never reaches them in the wild).
	if !p.tokenFed {
		for _, pad := range []string{" ", "\t", "\r", "  \t ", "\r\n", " "} {
			for _, variant := range []string{pad + canonStr, canonStr + pad, pad + canonStr + pad} {
				got, sentinel := p.parse(variant)
				if sentinel || got != canonVal {
					t.Fatalf("O-A1 ACCEPT: [%s] whitespace-padded %q parsed to (%v,sentinel=%v), want canonical %v (v=%d)",
						p.name, variant, got, sentinel, canonVal, v)
				}
			}
		}
	}

	// O-A2 FAIL-CLOSED: non-C-locale variants must be canon OR sentinel, never a
	// third finite value.
	decimalComma := strings.Replace(canonStr, fmt.Sprintf("%d", v), fmt.Sprintf("%d,5", v), 1) // "<v>,5 ..."
	variants := map[string]string{
		"decimal-comma":   decimalComma,
		"thousands-comma": groupThousands(canonStr),
		"nbsp-internal":   strings.Replace(canonStr, fmt.Sprintf("%d", v), insertNBSPInternal(v), 1),
		"ansi-wrapped":    ansiWrap(canonStr),
	}
	for kind, variant := range variants {
		if got, bad := oA2Misparse(p.parse, canonVal, variant); bad {
			t.Fatalf("O-A2 MISPARSE: [%s] %s variant %q parsed to non-sentinel %v, which is neither canonical %v nor the not-measured sentinel — a silent wrong-number (the #727/#862 class)",
				p.name, kind, variant, got, canonVal)
		}
	}
}

// oA2Misparse is the single predicate O-A2 enforces, factored out so the
// red-proof (TestSizeNumberFormatInvariant_RedProof) can drive the EXACT same
// oracle against a deliberately buggy parser and prove it has teeth. It reports
// bad=true iff `variant` parses to a non-sentinel value that differs from the
// canonical value (a silent wrong-number). A sentinel (not-measured) result is
// the allowed fail-closed direction and returns bad=false.
func oA2Misparse(parse func(string) (float64, bool), canonVal float64, variant string) (got float64, bad bool) {
	got, sentinel := parse(variant)
	if sentinel {
		return got, false
	}
	return got, got != canonVal
}

// insertNBSPInternal renders v with a U+00A0 inserted between its first digit and
// the rest, i.e. NBSP used as a (French-style) internal grouping separator — a
// shape that, if misparsed by stripping it, would yield a wrong number.
func insertNBSPInternal(v int64) string {
	d := fmt.Sprintf("%d", v)
	if len(d) < 2 {
		return d
	}
	return d[:1] + " " + d[1:]
}

// ── O-A3 smartctl NVMe thousands-separator equality ──────────────────────────

// nvmeCount parses a single NVMe count attribute via the REAL parseSMARTAttributes
// and returns the resulting MediaErrors (the counter whose value equals the raw).
func nvmeMediaErrors(rawField string) int64 {
	var s models.SMARTInfo
	parseSMARTAttributes("Media and Data Integrity Errors: "+rawField+"\n", &s)
	return s.MediaErrors
}

func checkSMARTThousands(t *testing.T, v int64) {
	plain := fmt.Sprintf("%d", v)
	grouped := groupThousands(plain)
	gotPlain := nvmeMediaErrors(plain)
	gotGrouped := nvmeMediaErrors(grouped)
	if gotPlain != v {
		t.Fatalf("O-A3 fixture: plain NVMe count %q parsed to MediaErrors=%d, want %d", plain, gotPlain, v)
	}
	if gotGrouped != gotPlain {
		t.Fatalf("O-A3 THOUSANDS-SEP DIVERGENCE: NVMe MediaErrors for grouped %q = %d, for plain %q = %d — comma-stripping is incomplete",
			grouped, gotGrouped, plain, gotPlain)
	}
}

// ── the fuzz target ──────────────────────────────────────────────────────────

func FuzzSizeNumberFormatInvariant(f *testing.F) {
	f.Add(uint64(1))
	f.Add(uint64(42))
	f.Add(uint64(512))
	f.Add(uint64(7183))
	f.Add(uint64(1234500))
	f.Add(uint64(9999999))

	parsers := sizeParsers()

	f.Fuzz(func(t *testing.T, raw uint64) {
		// Bound the magnitude so canonical rendering stays a clean integer well
		// inside int64 / float64-exact range; keep v >= 1 so canonical != sentinel.
		v := int64(raw%9_000_000) + 1

		for _, p := range parsers {
			checkSizeParser(t, p, v)
		}
		checkSMARTThousands(t, v)
	})
}
