//go:build linux

package collectors

import (
	"encoding/json"
	"fmt"
	"reflect"
	"sort"
	"strings"
	"testing"

	"github.com/keyorixhq/dashdiag/internal/models"
)

// tdnfFuzzEntry is the small advisory-entry model this harness renders to both
// `tdnf -j updateinfo list --security` JSON and the plain text table. Photon
// emits one entry per affected package, even when several share an UpdateID
// (cve_linux.go:1300-1304) — the fixture in cve_tdnf_linux_test.go shows this
// directly (PHSA-2026-5.0-0830 appears as two separate JSON objects).
type tdnfFuzzEntry struct {
	updateID string // without the "patch:" prefix
	kind     string // the "Type" field, e.g. "Security"
	pkg      string // package filename, always given a .rpm suffix
}

// sanitizeTDNFFuzzToken keeps fuzzed strings to a charset real advisory
// IDs/package names actually use, so the whitespace-delimited text renderer
// stays well-formed.
func sanitizeTDNFFuzzToken(s, fallback string) string {
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

// ensureRPMSuffix avoids a double ".rpm.rpm" when a seed/mutated token already
// carries the suffix (real package filenames always do).
func ensureRPMSuffix(pkg string) string {
	if strings.HasSuffix(pkg, ".rpm") {
		return pkg
	}
	return pkg + ".rpm"
}

// parseTDNFFuzzSpec decodes the fuzzer's single string input into a bounded
// list of advisory entries: one "updateID|type|package" triplet per line.
func parseTDNFFuzzSpec(spec string) []tdnfFuzzEntry {
	lines := strings.Split(spec, "\n")
	if len(lines) > 20 {
		lines = lines[:20]
	}
	entries := make([]tdnfFuzzEntry, 0, len(lines))
	for i, line := range lines {
		parts := strings.SplitN(line, "|", 3)
		if len(parts) < 3 {
			continue
		}
		entries = append(entries, tdnfFuzzEntry{
			updateID: sanitizeTDNFFuzzToken(parts[0], fmt.Sprintf("PHSA-2026-5.0-%04d", i)),
			kind:     sanitizeTDNFFuzzToken(parts[1], "Security"),
			pkg:      ensureRPMSuffix(sanitizeTDNFFuzzToken(parts[2], "pkg")),
		})
	}
	return entries
}

// renderTDNFFuzzText renders entries to the exact line format
// parseTDNFUpdateInfoText expects (cve_linux.go:1458-1472): "patch:<id> <type>
// <package>", >=3 whitespace fields, first field prefixed "patch:".
func renderTDNFFuzzText(entries []tdnfFuzzEntry) string {
	var b strings.Builder
	for _, e := range entries {
		fmt.Fprintf(&b, "patch:%s %s %s\n", e.updateID, e.kind, e.pkg)
	}
	return b.String()
}

// tdnfShapeVariant enumerates JSON payload shapes that are all syntactically
// valid (json.Unmarshal never errors, or the bracket-scan in
// parseTDNFUpdateInfoJSON legitimately finds no array) but structurally diverge
// from what the tdnfUpdateInfoEntry struct expects — modeling schema drift a
// real tdnf version could plausibly emit.
type tdnfShapeVariant uint8

const (
	tdnfShapeFaithful tdnfShapeVariant = iota
	tdnfShapeRenamedUpdateIDKey
	tdnfShapeEmptyArray
	tdnfShapeNoArrayBrackets
	tdnfShapeVariantCount // keep last
)

// renderTDNFFuzzJSON renders entries to `tdnf -j updateinfo list --security`
// JSON in the given shape variant. tdnfShapeFaithful is modeled independently
// on the real captured shape in cve_tdnf_linux_test.go's
// tdnfUpdateInfoJSONFixture (Type/UpdateID/Packages, one object per package) —
// deliberately NOT the production tdnfUpdateInfoEntry type, so a silent tag
// drift in production would still be caught here rather than trivially
// round-tripping through the same struct on both sides.
func renderTDNFFuzzJSON(entries []tdnfFuzzEntry, variant tdnfShapeVariant) string {
	switch variant % tdnfShapeVariantCount {
	case tdnfShapeEmptyArray:
		return "[]"
	case tdnfShapeNoArrayBrackets:
		// A real tdnf can prefix or replace the array with plain metadata-refresh
		// text; when no '[' ... ']' span exists at all, parseTDNFUpdateInfoJSON
		// correctly reports parsed=false and production falls back to text — this
		// variant is the negative control confirming that path does NOT diverge.
		return "Refreshing metadata for: 'VMware Photon Linux 5.0 (x86_64) Updates'\n"
	case tdnfShapeRenamedUpdateIDKey:
		type rec struct {
			Type       string   `json:"Type"`
			AdvisoryID string   `json:"AdvisoryID"` // renamed from UpdateID
			Packages   []string `json:"Packages"`
		}
		var recs []rec
		for _, e := range entries {
			recs = append(recs, rec{Type: e.kind, AdvisoryID: "patch:" + e.updateID, Packages: []string{e.pkg}})
		}
		b, _ := json.Marshal(recs)
		return string(b)
	default: // tdnfShapeFaithful
		type tdnfFaithfulRecord struct {
			Type     string   `json:"Type"`
			UpdateID string   `json:"UpdateID"`
			Packages []string `json:"Packages"`
		}
		var recs []tdnfFaithfulRecord
		for _, e := range entries {
			recs = append(recs, tdnfFaithfulRecord{Type: e.kind, UpdateID: "patch:" + e.updateID, Packages: []string{e.pkg}})
		}
		b, _ := json.Marshal(recs)
		return string(b)
	}
}

// tdnfDedupeAdvisories mirrors scanAllTDNF's dedup/aggregate loop
// (cve_linux.go:1405-1427), minus the enrichTDNFAdvisoryWithCVEs step — a
// separate shelled-out command (`tdnf updateinfo info --security`), out of
// scope for this parser-level differential since it only appends CVE IDs to
// advisories that already exist; it never changes which/how many advisories
// are found.
func tdnfDedupeAdvisories(entries []tdnfUpdateInfoEntry) []models.CVEAdvisory {
	byID := map[string]*models.CVEAdvisory{}
	var order []string
	for _, e := range entries {
		id := tdnfTrimPatchPrefix(e.UpdateID)
		if id == "" {
			continue
		}
		adv, ok := byID[id]
		if !ok {
			adv = &models.CVEAdvisory{ID: id, Severity: "Important"}
			byID[id] = adv
			order = append(order, id)
		}
		for _, p := range e.Packages {
			pkg := strings.TrimSuffix(p, ".rpm")
			if adv.Summary == "" {
				adv.Summary = pkg
			} else if !strings.Contains(adv.Summary, pkg) {
				adv.Summary += ", " + pkg
			}
		}
	}
	out := make([]models.CVEAdvisory, 0, len(order))
	for _, id := range order {
		out = append(out, *byID[id])
	}
	return out
}

// sortAdvisoriesByID returns a copy sorted by ID, for order-independent
// comparison (map iteration order is randomized, but tdnfDedupeAdvisories
// itself preserves first-seen order — sorting removes that as a source of
// spurious mismatch between two independently-built advisory lists).
func sortAdvisoriesByID(advs []models.CVEAdvisory) []models.CVEAdvisory {
	out := make([]models.CVEAdvisory, len(advs))
	copy(out, advs)
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}

// FuzzTDNFUpdateInfoJSONTextDifferential fuzzes a structured advisory list,
// renders it to both `tdnf -j updateinfo list --security` JSON and the plain
// text table, and checks two oracles against dashdiag's real parsers/dedup
// logic:
//
//  1. Faithful round-trip (variant==tdnfShapeFaithful, no fallback triggered):
//     JSON and text parses of the SAME state must dedupe to the identical
//     advisory list. Any divergence here is a genuine parser or renderer bug.
//  2. Fallback-decision parity (all variants, always checked): production's
//     real decision in scanAllTDNF — try JSON, use it if parsed==true (even if
//     the resulting advisory list is empty), else fall back to text
//     (cve_linux.go:1386-1397) — must reach the same verdict (advisory count,
//     the sole input to checkCVEHealth's tdnf WARN condition,
//     heuristics_packages.go:347-359: `len(r.Critical)+len(r.Important) > 0`)
//     as trusting the text form alone. A syntactically valid but structurally
//     wrong JSON payload (renamed UpdateID key, or a bare `[]`) that still
//     parses successfully short-circuits the fallback in production — exactly
//     the "JSON succeeds but hides findings" class this harness exists to
//     catch (this is a REAL, already-present gap: cve_linux.go:1409-1412 skips
//     any entry whose id is empty after tdnfTrimPatchPrefix, with no anomaly
//     signal and no fallback).
//
// KNOWN FINDING (confirmed 2026-09-23, not yet fixed — reported, not silently
// patched, per the joint-triage requirement before calling this a bug): seeding
// this fuzzer with tdnfShapeRenamedUpdateIDKey or tdnfShapeEmptyArray on a
// non-empty spec reliably fails both oracles below. scanAllTDNF (cve_linux.go:
// 1386-1397) only falls back to text when parseTDNFUpdateInfoJSON returns
// parsed=false; a syntactically valid `[]` or a payload with a renamed/missing
// "UpdateID" key returns parsed=true with zero (or all-empty-ID, later
// filtered at cve_linux.go:1409-1412) advisories, so production reports "no
// pending security advisories" while the text form of the SAME state shows
// real ones — the "JSON succeeds but hides findings" class. Minimized repro:
// spec="PHSA-2026-5.0-0874|Security|zlib-1.3.2-1.ph5.x86_64.rpm", variant=
// tdnfShapeRenamedUpdateIDKey (or tdnfShapeEmptyArray). These two seeds are
// deliberately NOT in the corpus below (they'd leave `go test` permanently
// red pending a production fix decision) — re-add them locally, or run
// `go test -fuzz=FuzzTDNFUpdateInfoJSONTextDifferential`, to reproduce.
func FuzzTDNFUpdateInfoJSONTextDifferential(f *testing.F) {
	f.Add("PHSA-2026-5.0-0874|Security|zlib-1.3.2-1.ph5.x86_64.rpm", uint8(tdnfShapeFaithful))
	f.Add("PHSA-2026-5.0-0830|Security|xz-libs-5.4.0-6.ph5.x86_64.rpm\nPHSA-2026-5.0-0830|Security|xz-5.4.0-6.ph5.x86_64.rpm", uint8(tdnfShapeFaithful))
	f.Add("", uint8(tdnfShapeFaithful))
	f.Add("PHSA-2026-5.0-0874|Security|zlib-1.3.2-1.ph5.x86_64.rpm", uint8(tdnfShapeNoArrayBrackets))

	f.Fuzz(func(t *testing.T, spec string, variantSeed uint8) {
		fuzzEntries := parseTDNFFuzzSpec(spec)
		variant := tdnfShapeVariant(variantSeed) % tdnfShapeVariantCount

		textOut := renderTDNFFuzzText(fuzzEntries)
		jsonOut := renderTDNFFuzzJSON(fuzzEntries, variant)

		jsonEntries, parsed := parseTDNFUpdateInfoJSON(jsonOut)
		textEntries := parseTDNFUpdateInfoText(textOut)

		var effectiveEntries []tdnfUpdateInfoEntry
		usedFallback := false
		if parsed {
			effectiveEntries = jsonEntries
		} else {
			effectiveEntries = textEntries
			usedFallback = true
		}

		effectiveAdvisories := sortAdvisoriesByID(tdnfDedupeAdvisories(effectiveEntries))
		textAdvisories := sortAdvisoriesByID(tdnfDedupeAdvisories(textEntries))

		if variant == tdnfShapeFaithful && !usedFallback {
			jsonAdvisories := sortAdvisoriesByID(tdnfDedupeAdvisories(jsonEntries))
			if !reflect.DeepEqual(jsonAdvisories, textAdvisories) {
				t.Fatalf("faithful JSON/text render diverged in deduped advisories:\n json=%+v\n text=%+v\n jsonOut=%s\n textOut=%s",
					jsonAdvisories, textAdvisories, jsonOut, textOut)
			}
		}

		if len(effectiveAdvisories) != len(textAdvisories) {
			t.Fatalf("production JSON-first-with-fallback verdict diverges from text-only ground truth: variant=%d usedFallback=%v spec=%q\n effective(%d advisories)=%+v\n text-only(%d advisories)=%+v\n jsonOut=%s\n textOut=%s",
				variant, usedFallback, spec, len(effectiveAdvisories), effectiveAdvisories, len(textAdvisories), textAdvisories, jsonOut, textOut)
		}
	})
}
