//go:build linux

package collectors

import "testing"

// parseSMARTHealth must return a verdict whenever smartctl prints one — including
// for a FAILING drive, whose `smartctl -H` exits non-zero but still prints
// "...result: FAILED!". Returning ok=false there would let collectSMART set an
// Error and the analysis layer would skip the drive entirely — silently dropping
// the one drive we most need to flag.
func TestParseSMARTHealth(t *testing.T) {
	cases := []struct {
		name        string
		out         string
		wantHealthy bool
		wantOK      bool
	}{
		{
			name:        "SATA/NVMe passed",
			out:         "smartctl 7.4\n\nSMART overall-health self-assessment test result: PASSED\n",
			wantHealthy: true, wantOK: true,
		},
		{
			name:        "SATA/NVMe failing (non-zero exit, verdict still on stdout)",
			out:         "smartctl 7.4\n\nSMART overall-health self-assessment test result: FAILED!\n",
			wantHealthy: false, wantOK: true,
		},
		{
			name:        "SAS OK",
			out:         "SMART Health Status: OK\n",
			wantHealthy: true, wantOK: true,
		},
		{
			name:        "SAS failing",
			out:         "SMART Health Status: FAILED\n",
			wantHealthy: false, wantOK: true,
		},
		{
			name:        "no verdict line",
			out:         "smartctl 7.4\nUnable to detect device type\n",
			wantHealthy: false, wantOK: false,
		},
		{
			name:        "empty output",
			out:         "",
			wantHealthy: false, wantOK: false,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			healthy, ok := parseSMARTHealth(tc.out)
			if healthy != tc.wantHealthy || ok != tc.wantOK {
				t.Errorf("parseSMARTHealth = (healthy=%v, ok=%v), want (%v, %v)",
					healthy, ok, tc.wantHealthy, tc.wantOK)
			}
		})
	}
}
