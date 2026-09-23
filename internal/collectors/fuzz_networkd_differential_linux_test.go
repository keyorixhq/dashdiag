//go:build linux

package collectors

import (
	"encoding/json"
	"fmt"
	"reflect"
	"strings"
	"testing"

	"github.com/keyorixhq/dashdiag/internal/models"
)

// uptimeWellPastBootSettle is an uptime value well past classifyNetworkdLinks'
// 300s boot-settle gate (networkd_config_linux.go:114), so a "configuring"/
// "pending" SETUP always classifies as genuinely stuck rather than a boot
// transient — matching the existing convention in
// TestParseNetworkctlLinksJSON/TestParseNetworkctlLinksColumns (99999).
const uptimeWellPastBootSettle = 99999

// networkctlFuzzLink is the small link-state model this harness renders to both
// `networkctl --json=short list` JSON and `networkctl list --no-legend` text.
type networkctlFuzzLink struct {
	name        string
	operational string
	setup       string
}

// sanitizeNetworkctlFuzzToken keeps fuzzed strings to a charset real interface
// names/state words actually use, so the text renderer's whitespace-delimited
// column format stays well-formed (a raw fuzzed string could otherwise contain
// spaces/newlines that would fabricate extra columns, which is a renderer
// artifact, not a parser input real `networkctl` would ever produce).
func sanitizeNetworkctlFuzzToken(s, fallback string) string {
	var b strings.Builder
	for _, r := range s {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == '-', r == '_', r == '.':
			b.WriteRune(r)
		}
	}
	out := b.String()
	if len(out) > 40 {
		out = out[:40]
	}
	if out == "" {
		return fallback
	}
	return out
}

// parseNetworkctlFuzzSpec decodes the fuzzer's single string input into a bounded
// list of links: one "name|operational|setup" triplet per line.
func parseNetworkctlFuzzSpec(spec string) []networkctlFuzzLink {
	lines := strings.Split(spec, "\n")
	if len(lines) > 20 {
		lines = lines[:20]
	}
	links := make([]networkctlFuzzLink, 0, len(lines))
	for i, line := range lines {
		parts := strings.SplitN(line, "|", 3)
		if len(parts) < 3 {
			continue
		}
		links = append(links, networkctlFuzzLink{
			name:        sanitizeNetworkctlFuzzToken(parts[0], fmt.Sprintf("eth%d", i)),
			operational: sanitizeNetworkctlFuzzToken(parts[1], "routable"),
			setup:       sanitizeNetworkctlFuzzToken(parts[2], "configured"),
		})
	}
	return links
}

// renderNetworkctlFuzzText renders links to the exact column layout
// parseNetworkctlLinksColumns expects (networkd_config_linux.go:151-168):
// IDX NAME TYPE OPERATIONAL SETUP, >=5 whitespace-fields, SETUP last,
// OPERATIONAL second-to-last. TYPE is display-only and ignored by the parser,
// so a constant placeholder is faithful.
func renderNetworkctlFuzzText(links []networkctlFuzzLink) string {
	var b strings.Builder
	for i, l := range links {
		fmt.Fprintf(&b, "%3d %s ether %s %s\n", i+1, l.name, l.operational, l.setup)
	}
	return b.String()
}

// networkctlShapeVariant enumerates JSON payload shapes that are all
// syntactically valid JSON (json.Unmarshal never errors) but structurally
// diverge from what parseNetworkctlLinksJSON's networkctlJSON struct expects —
// modeling schema drift (renamed field, older/newer schema, empty array) a real
// networkctl version could plausibly emit. This is the shape space step 3 of
// the task asks to cover: "JSON that PARSES but in a shape the parser doesn't
// expect ... must not produce zero failed links while the text form shows some."
// There is deliberately NO "always empty/missing-key regardless of input"
// variant: an earlier version of this harness had one (shapeMissingInterfacesKey
// forced `{}` even when links was non-empty), and it fabricated a state real
// networkctl can never produce — JSON reporting zero links while text, for the
// SAME underlying state, reports some. That's a renderer-model artifact, not a
// reachable bug (mirrors the equivalent fix in fuzz_tdnf_differential_linux_test.go).
// A genuinely empty link set already renders as empty in BOTH formats via
// shapeFaithful with zero links (empty spec) — see parseNetworkctlLinksJSON's
// doc comment for why that must stay trusted with no fallback.
type networkctlShapeVariant uint8

const (
	shapeFaithful networkctlShapeVariant = iota
	shapeRenamedAdminStateKey
	shapeVariantCount // keep last
)

// renderNetworkctlFuzzJSON renders links to `networkctl --json=short list` JSON
// in the given shape variant. shapeFaithful mirrors the real capture in
// testdata/differential/networkctl/ct223-ubuntu-systemd255-20260923.json (extra
// ignored keys included, independent of parseNetworkctlLinksJSON's own struct —
// see networkctlFaithfulIface below), so the faithful path also exercises
// "unknown fields are tolerated." shapeRenamedAdminStateKey is the one genuine
// per-field schema-drift a real networkctl version could plausibly emit.
func renderNetworkctlFuzzJSON(links []networkctlFuzzLink, variant networkctlShapeVariant) string {
	switch variant % shapeVariantCount {
	case shapeRenamedAdminStateKey:
		type iface struct {
			Index            int    `json:"Index"`
			Name             string `json:"Name"`
			Type             string `json:"Type"`
			OperationalState string `json:"OperationalState"`
			AdminState       string `json:"AdminState"` // renamed from AdministrativeState
		}
		doc := struct {
			Interfaces []iface `json:"Interfaces"`
		}{}
		for i, l := range links {
			doc.Interfaces = append(doc.Interfaces, iface{
				Index: i + 1, Name: l.name, Type: "ether",
				OperationalState: l.operational, AdminState: l.setup,
			})
		}
		b, _ := json.Marshal(doc)
		return string(b)
	default: // shapeFaithful
		// networkctlFaithfulIface is deliberately NOT the production
		// networkctlJSON type — it's modeled independently on the real capture
		// (extra Index/Type/MTU fields the parser ignores), so a silent drift
		// in production's own json tags would still be caught here instead of
		// trivially round-tripping through the same struct on both sides.
		type networkctlFaithfulIface struct {
			Index               int    `json:"Index"`
			Name                string `json:"Name"`
			Type                string `json:"Type"`
			MTU                 int    `json:"MTU"`
			OperationalState    string `json:"OperationalState"`
			AdministrativeState string `json:"AdministrativeState"`
		}
		doc := struct {
			Interfaces []networkctlFaithfulIface `json:"Interfaces"`
		}{}
		for i, l := range links {
			doc.Interfaces = append(doc.Interfaces, networkctlFaithfulIface{
				Index: i + 1, Name: l.name, Type: "ether", MTU: 1500,
				OperationalState: l.operational, AdministrativeState: l.setup,
			})
		}
		b, _ := json.Marshal(doc)
		return string(b)
	}
}

// normalizeLinks treats nil and empty as equal for comparison purposes,
// matching every real consumer of a []models.NetworkdLink (classifyNetworkdLinks
// and friends only ever check len()).
func normalizeLinks(links []models.NetworkdLink) []models.NetworkdLink {
	if links == nil {
		return []models.NetworkdLink{}
	}
	return links
}

// FuzzNetworkctlJSONTextDifferential fuzzes a structured link-state, renders it
// to both `networkctl --json=short list` JSON and `networkctl list --no-legend`
// text, and checks two oracles against dashdiag's real parsers/classifier:
//
//  1. Faithful round-trip (variant==shapeFaithful, no fallback triggered): JSON
//     and text parses of the SAME state must produce the identical normalized
//     link set. Any divergence here is a genuine parser or renderer bug, not an
//     intentional schema-drift scenario.
//  2. Fallback-decision parity (all variants, always checked): production's
//     real decision in collectNetworkdLinks — try JSON, use it if
//     parseNetworkctlLinksJSON returned non-nil, else fall back to text
//     (networkd_config_linux.go:96-105) — must reach the same verdict
//     (FailedLinks/StuckLinks counts, the sole inputs to checkNetworkdConfig's
//     WARN conditions in heuristics_networkd.go:67,87) as trusting the text
//     form alone. A syntactically valid but structurally wrong JSON payload
//     that still parses to a non-nil (possibly empty) result short-circuits the
//     fallback in production — exactly the "JSON succeeds but hides findings"
//     class this harness exists to catch.
//
// FIXED FINDING (2026-09-23, docs/findings/2026-09-23-FINDING-tdnf-json-schema-silent-empty.md):
// parseNetworkctlLinksJSON previously accepted a non-empty array even when
// every interface was missing AdministrativeState (e.g. a renamed key),
// silently returning Setup="" for every link (never matching "failed") and
// never falling back to text. The seed pairing shapeRenamedAdminStateKey with
// a FAILED link is the permanent regression for this — it now goes green
// because production correctly returns nil (distrust) and falls back.
func FuzzNetworkctlJSONTextDifferential(f *testing.F) {
	f.Add("eth0|routable|configured", uint8(shapeFaithful))
	f.Add("eth0|routable|configured\neth1|no-carrier|failed", uint8(shapeFaithful))
	f.Add("eth0|carrier|unmanaged\neth1|degraded|configuring", uint8(shapeFaithful))
	f.Add("", uint8(shapeFaithful))
	f.Add("eth0|no-carrier|failed\neth0|no-carrier|failed", uint8(shapeFaithful))
	f.Add("eth0|routable|configured", uint8(shapeRenamedAdminStateKey))
	// Pairs the schema-mismatch variant with a FAILED link, so the corpus
	// actually exercises the verdict-hiding scenario the fix closes — a
	// healthy-only seed can't distinguish a hidden Setup="" from a genuinely
	// healthy link at the verdict level.
	f.Add("eth0|no-carrier|failed", uint8(shapeRenamedAdminStateKey))

	f.Fuzz(func(t *testing.T, spec string, variantSeed uint8) {
		links := parseNetworkctlFuzzSpec(spec)
		variant := networkctlShapeVariant(variantSeed) % shapeVariantCount

		textOut := renderNetworkctlFuzzText(links)
		jsonOut := renderNetworkctlFuzzJSON(links, variant)

		jsonLinks := parseNetworkctlLinksJSON(jsonOut)
		textLinks := parseNetworkctlLinksColumns(textOut)

		if variant == shapeRenamedAdminStateKey && len(links) > 0 {
			// Pin the fix precisely: a non-empty array with every
			// AdministrativeState renamed away must be distrusted (nil), not
			// silently accepted with Setup=="".
			if jsonLinks != nil {
				t.Fatalf("renamed AdministrativeState key on a non-empty array must return nil (distrust), got %+v: jsonOut=%s", jsonLinks, jsonOut)
			}
		}

		var effective []models.NetworkdLink
		usedFallback := false
		if jsonLinks != nil {
			effective = jsonLinks
		} else {
			effective = textLinks
			usedFallback = true
		}

		if variant == shapeFaithful && !usedFallback {
			// parseNetworkctlLinksJSON always returns a non-nil (possibly
			// zero-length) slice, while parseNetworkctlLinksColumns leaves its
			// result nil when nothing matched — a difference production never
			// inspects (every consumer only ever checks len()), so normalize
			// nil-vs-empty before comparing to avoid a spurious mismatch here.
			if !reflect.DeepEqual(normalizeLinks(jsonLinks), normalizeLinks(textLinks)) {
				t.Fatalf("faithful JSON/text render diverged in parsed result:\n json=%+v\n text=%+v\n jsonOut=%s\n textOut=%s",
					jsonLinks, textLinks, jsonOut, textOut)
			}
		}

		ef, es := classifyNetworkdLinks(effective, uptimeWellPastBootSettle)
		tf, ts := classifyNetworkdLinks(textLinks, uptimeWellPastBootSettle)
		if len(ef) != len(tf) || len(es) != len(ts) {
			t.Fatalf("production JSON-first-with-fallback verdict diverges from text-only ground truth: variant=%d usedFallback=%v spec=%q\n effective(failed=%d,stuck=%d)=%+v\n text-only(failed=%d,stuck=%d)=%+v\n jsonOut=%s\n textOut=%s",
				variant, usedFallback, spec, len(ef), len(es), effective, len(tf), len(ts), textLinks, jsonOut, textOut)
		}
	})
}
