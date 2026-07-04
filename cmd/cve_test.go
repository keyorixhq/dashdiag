package cmd

import "testing"

func TestIsNixOS(t *testing.T) {
	cases := []struct {
		distroID string
		want     bool
	}{
		{"nixos", true},
		{"NixOS", true},
		{"ubuntu", false},
		{"", false},
	}
	for _, c := range cases {
		if got := isNixOS(c.distroID); got != c.want {
			t.Errorf("isNixOS(%q) = %v, want %v", c.distroID, got, c.want)
		}
	}
}
