//go:build linux

package collectors

import (
	"testing"

	"github.com/keyorixhq/dashdiag/internal/models"
)

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

// parseSMARTAttributes must never let a negative count reach a counter: the
// analysis layer flags a drive on `MediaErrors > 0`, so a garbled or hostile
// SMART log printing "-5" would slip under the threshold and read as healthy —
// a false-OK. Valid non-negative values must still parse.
func TestParseSMARTAttributesNegativeRejected(t *testing.T) {
	var s models.SMARTInfo
	parseSMARTAttributes(
		"Media and Data Integrity Errors:  -5\n"+
			"Percentage Used:  -3%\n"+
			"Power On Hours:  -1\n",
		&s)
	if s.MediaErrors != 0 || s.PercentUsed != 0 || s.PowerOnHours != 0 {
		t.Errorf("negative SMART values leaked into counters: media=%d pct=%d poh=%d (want 0,0,0)",
			s.MediaErrors, s.PercentUsed, s.PowerOnHours)
	}

	// Valid values must still be read.
	var ok models.SMARTInfo
	parseSMARTAttributes(
		"Media and Data Integrity Errors:  2\n"+
			"Percentage Used:  7%\n"+
			"Power On Hours:  7,183\n",
		&ok)
	if ok.MediaErrors != 2 || ok.PercentUsed != 7 || ok.PowerOnHours != 7183 {
		t.Errorf("valid SMART values mis-parsed: media=%d pct=%d poh=%d (want 2,7,7183)",
			ok.MediaErrors, ok.PercentUsed, ok.PowerOnHours)
	}
}
