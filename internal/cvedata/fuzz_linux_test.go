//go:build linux

package cvedata

import (
	"strings"
	"testing"
)

// FuzzParseUbuntuOVAL fuzzes the Ubuntu/Debian OVAL XML parser.
// OVAL feeds are fetched from Ubuntu's servers; a compromised or malformed
// feed must not panic — it must return an error instead.
//
// Invariants on success (err == nil):
//   - every entry carries a CVE-prefixed ID
//   - every entry's CVSS score is >= 0
//
// Seeds cover the two comment forms the parser handles ("DPKG is earlier than"
// and "is affected and may need fixing"), the skip path (non-vulnerability
// class), and common degenerate inputs (empty, truncated, non-XML).
func FuzzParseUbuntuOVAL(f *testing.F) {
	f.Add(`<?xml version="1.0"?>
<oval_definitions>
  <definitions>
    <definition class="vulnerability">
      <metadata>
        <reference source="CVE" ref_id="CVE-2024-1234"/>
        <advisory><severity>high</severity></advisory>
      </metadata>
      <criteria>
        <criterion comment="bash DPKG is earlier than 5.0"/>
      </criteria>
    </definition>
  </definitions>
</oval_definitions>`)
	f.Add(`<?xml version="1.0"?>
<oval_definitions>
  <definitions>
    <definition class="vulnerability">
      <metadata>
        <reference source="CVE" ref_id="CVE-2024-9999"/>
        <advisory><severity>medium</severity></advisory>
      </metadata>
      <criteria>
        <criterion comment="openssl package in noble is affected and may need fixing"/>
      </criteria>
    </definition>
  </definitions>
</oval_definitions>`)
	// Non-vulnerability class — must be silently skipped, not crash.
	f.Add(`<?xml version="1.0"?><oval_definitions><definitions><definition class="patch"></definition></definitions></oval_definitions>`)
	// Empty definitions list.
	f.Add(`<?xml version="1.0"?><oval_definitions><definitions></definitions></oval_definitions>`)
	// Degenerate: not XML.
	f.Add(`not xml at all`)
	f.Add(``)
	f.Add(`<`)
	f.Add(`<oval_definitions>`)

	f.Fuzz(func(t *testing.T, data string) {
		entries, err := parseUbuntuOVALVersionAware(strings.NewReader(data))
		if err != nil {
			return
		}
		for i, e := range entries {
			if !strings.HasPrefix(e.cveID, "CVE-") {
				t.Fatalf("entry[%d].cveID = %q, want CVE- prefix", i, e.cveID)
			}
			if e.cvss < 0 {
				t.Fatalf("entry[%d].cvss = %v, want >= 0", i, e.cvss)
			}
		}
	})
}
