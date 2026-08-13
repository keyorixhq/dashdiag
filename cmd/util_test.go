package cmd

import (
	"testing"
	"time"
)

// TestValidateWatchInterval is the regression test for cmd-13-05: cobra's
// DurationVar accepts "0s" or a negative duration string for --watch-interval
// with no complaint, and time.NewTicker(d) panics for any d <= 0. Every
// --watch command must reject a non-positive interval before it ever reaches
// time.NewTicker.
func TestValidateWatchInterval(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name    string
		d       time.Duration
		wantErr bool
	}{
		{"negative", -1 * time.Second, true},
		{"zero", 0, true},
		{"one nanosecond (boundary, just above zero)", 1, false},
		{"typical positive", 5 * time.Second, false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			err := validateWatchInterval(tc.d)
			if tc.wantErr && err == nil {
				t.Errorf("validateWatchInterval(%s) = nil, want error", tc.d)
			}
			if !tc.wantErr && err != nil {
				t.Errorf("validateWatchInterval(%s) = %v, want nil", tc.d, err)
			}
		})
	}
}
