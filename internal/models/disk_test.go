package models

import "testing"

// TestSMARTInfo_NoRealTelemetry exercises the 6-of-7 sentinel threshold in
// NoRealTelemetry (disk.go): the all-sentinel-zero "virtual disk" true case,
// one true case per single field flipped to a real (non-sentinel) value in
// turn (a lone stray field must NOT defeat the detector — internal-models-03-01),
// a false case for two-or-more non-zero fields (genuine telemetry), and
// Healthy=false — per the table-driven boundary-test rule in CLAUDE.md.
func TestSMARTInfo_NoRealTelemetry(t *testing.T) {
	t.Parallel()

	allSentinel := SMARTInfo{
		Device:          "nvme0n1",
		Healthy:         true,
		Temperature:     0,
		AvailableSpare:  0,
		PercentUsed:     0,
		MediaErrors:     0,
		PowerOnHours:    0,
		PowerCycles:     0,
		UnsafeShutdowns: 0,
	}

	tests := []struct {
		name string
		in   SMARTInfo
		want bool
	}{
		{
			name: "all sentinel zero + healthy = true (virtual disk signature)",
			in:   allSentinel,
			want: true,
		},
		{
			name: "healthy false short-circuits even with all sentinels",
			in: func() SMARTInfo {
				s := allSentinel
				s.Healthy = false
				return s
			}(),
			want: false,
		},
		{
			// A single stray non-zero field (parser quirk, or a virtual device
			// that happens to pass through one real counter) must not defeat
			// the detector — internal-models-03-01. 6 of 7 fields still
			// sentinel-zero clears the threshold.
			name: "lone real temperature does not defeat the detector (6-of-7 sentinel)",
			in: func() SMARTInfo {
				s := allSentinel
				s.Temperature = 35
				return s
			}(),
			want: true,
		},
		{
			name: "negative temperature still counts as reported (not <= 0 sentinel path skipped)",
			in: func() SMARTInfo {
				s := allSentinel
				s.Temperature = -5
				return s
			}(),
			want: true, // Temperature <= 0 is true for negative too, so this stays a sentinel match
		},
		{
			name: "lone non-zero available spare does not defeat the detector",
			in: func() SMARTInfo {
				s := allSentinel
				s.AvailableSpare = 100
				return s
			}(),
			want: true,
		},
		{
			name: "lone non-zero percent used does not defeat the detector",
			in: func() SMARTInfo {
				s := allSentinel
				s.PercentUsed = 3
				return s
			}(),
			want: true,
		},
		{
			name: "lone non-zero media errors does not defeat the detector",
			in: func() SMARTInfo {
				s := allSentinel
				s.MediaErrors = 1
				return s
			}(),
			want: true,
		},
		{
			name: "lone non-zero power on hours does not defeat the detector",
			in: func() SMARTInfo {
				s := allSentinel
				s.PowerOnHours = 500
				return s
			}(),
			want: true,
		},
		{
			name: "lone non-zero power cycles does not defeat the detector",
			in: func() SMARTInfo {
				s := allSentinel
				s.PowerCycles = 10
				return s
			}(),
			want: true,
		},
		{
			name: "lone non-zero unsafe shutdowns does not defeat the detector",
			in: func() SMARTInfo {
				s := allSentinel
				s.UnsafeShutdowns = 2
				return s
			}(),
			want: true,
		},
		{
			// Two non-zero fields crosses the 6-of-7 threshold (only 5 remain
			// sentinel-zero) — this is real telemetry, not a lone stray field.
			name: "two non-zero fields cross the threshold (real telemetry, not a stray)",
			in: func() SMARTInfo {
				s := allSentinel
				s.PowerOnHours = 500
				s.PowerCycles = 10
				return s
			}(),
			want: false,
		},
		{
			name: "all fields real (genuine healthy drive)",
			in: SMARTInfo{
				Device: "nvme0n1", Healthy: true, Temperature: 38,
				AvailableSpare: 100, PercentUsed: 2, MediaErrors: 0,
				PowerOnHours: 8760, PowerCycles: 42, UnsafeShutdowns: 1,
			},
			want: false,
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := tt.in.NoRealTelemetry(); got != tt.want {
				t.Errorf("NoRealTelemetry() = %v, want %v (in=%+v)", got, tt.want, tt.in)
			}
		})
	}
}
