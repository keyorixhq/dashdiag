package analysis

import "testing"

// DeepTCPCounterLevel is the single source of truth shared by the health
// heuristics and the `dsd net` renderer, so its floor/rate boundaries are locked
// here directly. The key property: a cumulative since-boot total is rate-normalized
// against uptime, so a small or ancient count never escalates the way the raw
// total used to (e.g. a lone listen overflow on a long-lived host is INFO, not CRIT).
func TestDeepTCPCounterLevel(t *testing.T) {
	const day = 86400.0 // seconds — a 1-day-uptime host
	tests := []struct {
		name      string
		kind      string
		count     int
		uptimeSec float64
		want      string
	}{
		// syn_retrans: floor 100, WARN at ≥60/hr, never CRIT.
		{"syn_retrans below floor", "syn_retrans", 100, day, ""},
		{"syn_retrans large but old is INFO", "syn_retrans", 1000, day, "INFO"}, // ~42/hr
		{"syn_retrans sustained is WARN", "syn_retrans", 5000, 3600, "WARN"},    // 5000/hr
		{"syn_retrans no CRIT tier", "syn_retrans", 1_000_000, 3600, "WARN"},
		{"syn_retrans unknown uptime is INFO", "syn_retrans", 9999, 0, "INFO"},

		// listen_overflow: floor 0, WARN at ≥1/hr, CRIT at ≥10/hr.
		{"listen zero is clean", "listen_overflow", 0, day, ""},
		{"listen lone overflow long uptime is INFO", "listen_overflow", 1, day, "INFO"},
		{"listen lone overflow unknown uptime is INFO", "listen_overflow", 1, 0, "INFO"},
		{"listen low rate is WARN", "listen_overflow", 5, 3600, "WARN"}, // 5/hr
		{"listen sustained is CRIT", "listen_overflow", 5000, 3600, "CRIT"},

		// retrans_fail: floor 10, WARN at ≥6/hr, never CRIT.
		{"retrans_fail below floor", "retrans_fail", 10, 3600, ""},
		{"retrans_fail old total is INFO", "retrans_fail", 50, day, "INFO"}, // ~2/hr
		{"retrans_fail sustained is WARN", "retrans_fail", 100, 3600, "WARN"},
		{"retrans_fail unknown uptime is INFO", "retrans_fail", 500, 0, "INFO"},

		{"unknown kind is empty", "bogus", 9999, 3600, ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := DeepTCPCounterLevel(tt.kind, tt.count, tt.uptimeSec); got != tt.want {
				t.Errorf("DeepTCPCounterLevel(%q, %d, %.0f) = %q, want %q",
					tt.kind, tt.count, tt.uptimeSec, got, tt.want)
			}
		})
	}
}
