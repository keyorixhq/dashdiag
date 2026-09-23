//go:build linux

package collectors

import (
	"os"
	"testing"

	"github.com/keyorixhq/dashdiag/internal/models"
)

// TestNetworkctlDifferentialRealPairs verifies real, dashdiag-independent
// captures of `networkctl --json=short list` and `networkctl list --no-legend`
// from the SAME host at the SAME moment parse to an equivalent verdict via
// production's classifyNetworkdLinks. Captured manually over ssh/pct exec (not
// via dsd) — see testdata/differential/networkctl/manifest.json for hosts,
// exit codes, and provenance.
func TestNetworkctlDifferentialRealPairs(t *testing.T) {
	cases := []struct {
		name       string
		jsonFile   string
		jsonExit   int
		textFile   string
		wantFailed int
		wantStuck  int
	}{
		{
			name:       "pve01 host: systemd-networkd not running, JSON call exits 1 (real fallback trigger)",
			jsonFile:   "../../testdata/differential/networkctl/pve01-host-debian13-nonetworkd-20260923.json",
			jsonExit:   1,
			textFile:   "../../testdata/differential/networkctl/pve01-host-debian13-nonetworkd-20260923.text",
			wantFailed: 0,
			wantStuck:  0,
		},
		{
			name:       "ct223 dashdiag-demo: JSON call succeeds, healthy baseline",
			jsonFile:   "../../testdata/differential/networkctl/ct223-ubuntu-systemd255-20260923.json",
			jsonExit:   0,
			textFile:   "../../testdata/differential/networkctl/ct223-ubuntu-systemd255-20260923.text",
			wantFailed: 0,
			wantStuck:  0,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			jsonBytes, err := os.ReadFile(tc.jsonFile)
			if err != nil {
				t.Fatalf("reading %s: %v", tc.jsonFile, err)
			}
			textBytes, err := os.ReadFile(tc.textFile)
			if err != nil {
				t.Fatalf("reading %s: %v", tc.textFile, err)
			}

			// Mirrors collectNetworkdLinks' real decision (networkd_config_linux.go:96):
			// the JSON call's exit code gates whether its stdout is even offered to
			// parseNetworkctlLinksJSON at all — a non-zero exit means production goes
			// straight to text without ever attempting the JSON parse.
			var effective []models.NetworkdLink
			if tc.jsonExit == 0 {
				if links := parseNetworkctlLinksJSON(string(jsonBytes)); links != nil {
					effective = links
				}
			}
			textLinks := parseNetworkctlLinksColumns(string(textBytes))
			if effective == nil {
				effective = textLinks
			}

			ef, es := classifyNetworkdLinks(effective, uptimeWellPastBootSettle)
			tf, ts := classifyNetworkdLinks(textLinks, uptimeWellPastBootSettle)

			if len(ef) != tc.wantFailed || len(es) != tc.wantStuck {
				t.Errorf("effective verdict = failed=%d stuck=%d, want failed=%d stuck=%d (links=%+v)",
					len(ef), len(es), tc.wantFailed, tc.wantStuck, effective)
			}
			if len(ef) != len(tf) || len(es) != len(ts) {
				t.Errorf("production decision diverges from text-only ground truth: effective(failed=%d,stuck=%d) text-only(failed=%d,stuck=%d)",
					len(ef), len(es), len(tf), len(ts))
			}
		})
	}
}
