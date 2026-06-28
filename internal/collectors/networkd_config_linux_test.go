//go:build linux

package collectors

import (
	"os"
	"testing"

	"github.com/keyorixhq/dashdiag/internal/models"
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

func TestParseNetworkctlLinksJSON(t *testing.T) {
	got := parseNetworkctlLinksJSON(networkctlJSONFixture)
	if len(got) != 3 { // ALL links now (lo, eth0, eth1) — classification happens later
		t.Fatalf("want 3 links, got %d: %+v", len(got), got)
	}
	failed, _ := classifyNetworkdLinks(got, 99999)
	if len(failed) != 1 || failed[0].Name != "eth1" || failed[0].Operational != "no-carrier" {
		t.Errorf("eth1 should classify as failed: %+v", failed)
	}
	// Garbage → nil so the caller falls back to column parsing.
	if parseNetworkctlLinksJSON("not json") != nil {
		t.Error("non-JSON must return nil (triggers column fallback)")
	}
}

// Real `networkctl list --no-legend` columns: IDX LINK TYPE OPERATIONAL SETUP.
func TestParseNetworkctlLinksColumns(t *testing.T) {
	const out = "  1 lo   loopback carrier    unmanaged\n" +
		"  2 eth0 ether    routable   configured\n" +
		"  3 eth1 ether    no-carrier failed\n"
	got := parseNetworkctlLinksColumns(out)
	if len(got) != 3 {
		t.Fatalf("want 3 links, got %+v", got)
	}
	failed, _ := classifyNetworkdLinks(got, 99999)
	if len(failed) != 1 || failed[0].Name != "eth1" {
		t.Fatalf("want only eth1 failed, got %+v", failed)
	}
}

// A link stuck in SETUP=configuring is a STUCK fault only once boot has settled
// (uptime gate) — at boot it's a normal transient and must not flag.
func TestClassifyNetworkdLinks_StuckUptimeGated(t *testing.T) {
	links := []models.NetworkdLink{
		{Name: "eth0", Setup: "configured", Operational: "routable"},
		{Name: "eth1", Setup: "configuring", Operational: "no-carrier"},
		{Name: "lo", Setup: "unmanaged", Operational: "carrier"},
	}
	// Fresh boot (uptime 30s) — configuring is a transient, not stuck.
	if _, stuck := classifyNetworkdLinks(links, 30); len(stuck) != 0 {
		t.Errorf("configuring at boot must NOT be stuck, got %+v", stuck)
	}
	// Long after boot — still configuring = genuinely stuck.
	_, stuck := classifyNetworkdLinks(links, 6000)
	if len(stuck) != 1 || stuck[0].Name != "eth1" {
		t.Fatalf("configuring long after boot must be stuck, got %+v", stuck)
	}
}
