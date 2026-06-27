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

// Faithful to the key names emitted by `networkctl --json=short list` on systemd
// 253 (Photon 5.0): Name / OperationalState / AdministrativeState (+ many other
// keys the parser ignores). lo is unmanaged, eth0 configured, eth1 failed.
const networkctlJSONFixture = `{"Interfaces":[` +
	`{"Index":1,"Name":"lo","Type":"loopback","MTU":65536,"OperationalState":"carrier","AdministrativeState":"unmanaged"},` +
	`{"Index":2,"Name":"eth0","Type":"ether","MTU":1500,"OperationalState":"routable","AdministrativeState":"configured"},` +
	`{"Index":3,"Name":"eth1","Type":"ether","MTU":1500,"OperationalState":"no-carrier","AdministrativeState":"failed"}` +
	`]}`

func TestParseNetworkctlJSON(t *testing.T) {
	got := parseNetworkctlJSON(networkctlJSONFixture)
	if len(got) != 1 {
		t.Fatalf("want 1 failed link, got %d: %+v", len(got), got)
	}
	if got[0].Name != "eth1" || got[0].Setup != "failed" || got[0].Operational != "no-carrier" {
		t.Errorf("unexpected failed link: %+v", got[0])
	}
	// Garbage → nil so the caller falls back to column parsing.
	if parseNetworkctlJSON("not json") != nil {
		t.Error("non-JSON must return nil (triggers column fallback)")
	}
}

// Real `networkctl list --no-legend` columns: IDX LINK TYPE OPERATIONAL SETUP.
func TestParseNetworkctlColumns(t *testing.T) {
	const out = "  1 lo   loopback carrier    unmanaged\n" +
		"  2 eth0 ether    routable   configured\n" +
		"  3 eth1 ether    no-carrier failed\n"
	got := parseNetworkctlColumns(out)
	if len(got) != 1 || got[0].Name != "eth1" || got[0].Setup != "failed" {
		t.Fatalf("want only eth1 failed, got %+v", got)
	}
}
