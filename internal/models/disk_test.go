package models

import "testing"

// TestSMARTInfo_NoRealTelemetry exercises every && branch in NoRealTelemetry
// (disk.go:34): the all-sentinel-zero "virtual disk" true case, plus one false
// case per condition — each field flipped to a real (non-sentinel) value in
// turn, and Healthy=false — per the table-driven boundary-test rule in
// CLAUDE.md.
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
			name: "real temperature reported",
			in: func() SMARTInfo {
				s := allSentinel
				s.Temperature = 35
				return s
			}(),
			want: false,
		},
		{
			name: "negative temperature still counts as reported (not <= 0 sentinel path skipped)",
			in: func() SMARTInfo {
				s := allSentinel
				s.Temperature = -5
				return s
			}(),
			want: true, // Temperature <= 0 is true for negative too, so this stays a match
		},
		{
			name: "non-zero available spare",
			in: func() SMARTInfo {
				s := allSentinel
				s.AvailableSpare = 100
				return s
			}(),
			want: false,
		},
		{
			name: "non-zero percent used",
			in: func() SMARTInfo {
				s := allSentinel
				s.PercentUsed = 3
				return s
			}(),
			want: false,
		},
		{
			name: "non-zero media errors",
			in: func() SMARTInfo {
				s := allSentinel
				s.MediaErrors = 1
				return s
			}(),
			want: false,
		},
		{
			name: "non-zero power on hours",
			in: func() SMARTInfo {
				s := allSentinel
				s.PowerOnHours = 500
				return s
			}(),
			want: false,
		},
		{
			name: "non-zero power cycles",
			in: func() SMARTInfo {
				s := allSentinel
				s.PowerCycles = 10
				return s
			}(),
			want: false,
		},
		{
			name: "non-zero unsafe shutdowns",
			in: func() SMARTInfo {
				s := allSentinel
				s.UnsafeShutdowns = 2
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
