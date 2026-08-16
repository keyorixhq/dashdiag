package platform

import "testing"

func TestNetworkAllowed(t *testing.T) {
	tests := []struct {
		name         string
		offline      string
		allowNetwork string
		want         bool
	}{
		{"default (neither set)", "", "", false},
		{"DSD_ALLOW_NETWORK opts in", "", "1", true},
		{"DSD_OFFLINE forces offline even alone", "1", "", false},
		{
			// The security-relevant invariant: DSD_OFFLINE must win over
			// DSD_ALLOW_NETWORK (which is what --network sets — see
			// applyNetworkPolicy in cmd/root.go) no matter what value
			// DSD_ALLOW_NETWORK holds. A conflicting pair of signals must
			// resolve to the SAFE direction (no network), never the other way.
			"DSD_OFFLINE overrides DSD_ALLOW_NETWORK when both set", "1", "1", false,
		},
		{"DSD_OFFLINE empty string does not count as set", "", "1", true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Setenv("DSD_OFFLINE", tt.offline)
			t.Setenv("DSD_ALLOW_NETWORK", tt.allowNetwork)
			if got := NetworkAllowed(); got != tt.want {
				t.Errorf("NetworkAllowed() with DSD_OFFLINE=%q DSD_ALLOW_NETWORK=%q = %v, want %v",
					tt.offline, tt.allowNetwork, got, tt.want)
			}
		})
	}
}
