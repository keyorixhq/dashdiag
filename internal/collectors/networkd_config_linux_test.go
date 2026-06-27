//go:build linux

package collectors

import (
	"os"
	"testing"
)

// systemd-networkd runs as an unprivileged dynamic user, so it can only read a
// config file that has the world-read bit. 0644/0444 are fine; 0600/0640 (the
// common root-created case on Photon) are silently ignored.
func TestNetworkdCanRead(t *testing.T) {
	cases := []struct {
		mode os.FileMode
		want bool
	}{
		{0o644, true},
		{0o444, true},
		{0o664, true},
		{0o600, false}, // the Photon footgun
		{0o640, false}, // group-readable but not other-readable
		{0o660, false},
	}
	for _, tc := range cases {
		if got := networkdCanRead(tc.mode); got != tc.want {
			t.Errorf("networkdCanRead(%04o) = %v, want %v", tc.mode.Perm(), got, tc.want)
		}
	}
}
