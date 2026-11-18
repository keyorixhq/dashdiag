//go:build linux

package cvedata

import (
	"encoding/xml"
	"math"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// FuzzParseRHELOVALVerdict fuzzes ParseRHELOVAL — the Red Hat / Rocky / Alma /
// CentOS / Fedora OVAL entry point — which feeds an OVAL feed file (downloaded
// from a vendor mirror, or dropped into a standard path) to three sinks
// dashdiag calls directly: compress/bzip2.NewReader, the boundDecompressed
// io.LimitReader cap, and encoding/xml.NewDecoder.Decode. A compromised or
// corrupt feed must never crash the scan, exhaust memory, or — worse — come
// back with a WRONG severity that under-states a real CVE.
//
// Existing coverage: FuzzParseUbuntuOVAL fuzzes the Ubuntu reader-based helper
// parseUbuntuOVALVersionAware. It does NOT cover the RHEL-family path, which has
// its OWN independent decode step (bzip2 + file open + the 0-definitions guard)
// and does not call loadOVAL.
//
// Oracle (false-negative-guard verdict + never-panic, not crash-only):
//   - never panics on arbitrary bytes, whether the file is named .xml or .bz2
//     (the .bz2 name routes through bzip2.NewReader);
//   - FALSE-NEGATIVE GUARD (the verdict property): ParseRHELOVAL must NOT return
//     a nil error for a feed that contains zero <definition> elements. A feed
//     that is truncated, is a CDN/object-storage error body, or simply isn't
//     OVAL must fail loudly, because a silent empty-success makes the whole scan
//     report "no vulnerable packages found" — a WRONG VERDICT that hides every
//     vulnerable package on the host. So on success for a plain-XML input, the
//     raw bytes must contain a "<definition" element start.
//   - internal consistency (cheap sanity, not independently red-provable): the
//     map key equals rec.CVEID, the ID is an upper-cased CVE- identifier, and
//     CVSS3 is finite and >= 0 (the latter is double-defended by the
//     `score > bestScore` filter, so it is a belt-and-suspenders check).
//
// INVARIANT (see INVARIANTS.d note): ParseRHELOVAL never succeeds silently on a
// definition-less feed, and every returned key is a canonical CVE id equal to
// its record's CVEID.
//
// What this oracle does NOT verify: that every genuinely-affected package that
// IS present is reported (no field-level independent re-parse), the correctness
// of the decoded component/state/severity fields, or a bzip2 happy-path decode
// (stdlib has no bzip2 writer, so valid .bz2 happy-path bytes are not seeded —
// the .bz2 branch is exercised for robustness on malformed input only).

func writeOVAL(tb testing.TB, name string, data []byte) string {
	tb.Helper()
	p := filepath.Join(tb.TempDir(), name)
	if err := os.WriteFile(p, data, 0o600); err != nil {
		tb.Fatalf("write oval: %v", err)
	}
	return p
}

func FuzzParseRHELOVALVerdict(f *testing.F) {
	good := `<?xml version="1.0"?>
<oval_definitions><definitions>
  <definition class="vulnerability">
    <metadata>
      <reference source="CVE" ref_id="CVE-2024-3094"/>
      <advisory><severity>Important</severity>
        <cve cvss3="9.1/CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" impact="important">CVE-2024-3094</cve>
        <affected><resolution state="Affected"><component>xz</component></resolution></affected>
      </advisory>
    </metadata>
  </definition>
</definitions></oval_definitions>`
	// The NaN trap: a cvss3 attribute whose score field is "NaN". parseCVSS3Attr
	// must turn this into 0, not a NaN that silently understates severity.
	nanScore := strings.Replace(good, "9.1/CVSS:3.1", "NaN/CVSS:3.1", 1)
	infScore := strings.Replace(good, "9.1/CVSS:3.1", "Inf/CVSS:3.1", 1)

	f.Add([]byte(good), false)
	f.Add([]byte(nanScore), false)
	f.Add([]byte(infScore), false)
	f.Add([]byte(`<oval_definitions><definitions></definitions></oval_definitions>`), false)
	f.Add([]byte(good), true) // routed through bzip2.NewReader (not valid bz2 -> decode error)
	f.Add([]byte("not xml"), false)
	f.Add([]byte(""), false)
	f.Add([]byte("BZh"), true)

	f.Fuzz(func(t *testing.T, data []byte, asBz2 bool) {
		name := "rhel.oval.xml"
		if asBz2 {
			name = "rhel.oval.xml.bz2"
		}
		result, err := ParseRHELOVAL(writeOVAL(t, name, data))
		if err != nil {
			return // a parse/decompress error is the correct, safe outcome
		}
		// FALSE-NEGATIVE GUARD: a nil error means ParseRHELOVAL claims this was a
		// valid OVAL feed. For a plain-XML input (no bzip2 layer in the way) that
		// is only legitimate if the bytes actually decoded at least one
		// <definition>. Independently decode the same minimal struct (accessible
		// in-package) and assert consistency: a silent empty-success on a
		// definition-less feed would make the scan report "no vulnerable
		// packages" — the exact false-negative the 0-definitions guard prevents.
		if !asBz2 {
			var indep rhOVALDefs
			if xml.Unmarshal(data, &indep) == nil && len(indep.Definitions) == 0 {
				t.Fatalf("ParseRHELOVAL returned nil error for a feed that decodes to 0 <definition> elements (len=%d) — a definition-less feed must fail loudly, not silently scan clean", len(data))
			}
		}
		for id, rec := range result {
			if id != rec.CVEID {
				t.Fatalf("map key %q != record CVEID %q", id, rec.CVEID)
			}
			if !strings.HasPrefix(rec.CVEID, "CVE-") {
				t.Fatalf("CVEID %q lacks CVE- prefix", rec.CVEID)
			}
			if rec.CVEID != strings.ToUpper(rec.CVEID) {
				t.Fatalf("CVEID %q is not upper-cased", rec.CVEID)
			}
			if math.IsNaN(rec.CVSS3) || math.IsInf(rec.CVSS3, 0) {
				t.Fatalf("CVE %s has a non-finite CVSS3 score %v — a NaN/Inf score silently understates severity in every threshold comparison", rec.CVEID, rec.CVSS3)
			}
			if rec.CVSS3 < 0 {
				t.Fatalf("CVE %s has a negative CVSS3 score %v", rec.CVEID, rec.CVSS3)
			}
		}
	})
}
