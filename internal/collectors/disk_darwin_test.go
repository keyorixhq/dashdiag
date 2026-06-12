//go:build darwin

package collectors

import "testing"

// darwinSMARTStatus is the single source of truth for mapping a `diskutil info`
// "SMART Status:" value to a verdict, shared by the SATADevice (dsd health) and
// PhysicalDrive (dsd disk) darwin paths. The two cases that matter:
//   - "Failing" must be a real FAILED verdict (read=true, ok=false) → CRIT, not
//     swallowed into Error where the analysis layer silently skips it.
//   - "Not Supported"/unknown is NOT a verdict (read=false) → "SMART not read"
//     INFO, never a false pass and never a false fail.
func TestDarwinSMARTStatus(t *testing.T) {
	cases := []struct {
		status   string
		wantRead bool
		wantOK   bool
	}{
		{"Verified", true, true},
		{"verified", true, true}, // case-insensitive
		{"Passed", true, true},
		{"Failing", true, false},
		{"Not Supported", false, false},
		{"", false, false},
		{"gibberish", false, false},
	}
	for _, c := range cases {
		t.Run(c.status, func(t *testing.T) {
			read, ok := darwinSMARTStatus(c.status)
			if read != c.wantRead || ok != c.wantOK {
				t.Errorf("darwinSMARTStatus(%q) = (read=%v, ok=%v), want (%v, %v)",
					c.status, read, ok, c.wantRead, c.wantOK)
			}
		})
	}
}
