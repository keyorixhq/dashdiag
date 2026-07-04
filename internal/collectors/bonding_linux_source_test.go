//go:build linux

package collectors

import (
	"testing"

	"github.com/keyorixhq/dashdiag/internal/source"
)

func TestParseBondFileFromSource(t *testing.T) {
	withFixtureSource(t, func(b *source.Bundle) {
		b.PutFile("/proc/net/bonding/bond0", []byte(
			"Ethernet Channel Bonding Driver: v6.6.0\n"+
				"\n"+
				"Bonding Mode: fault-tolerance (active-backup)\n"+
				"Currently Active Slave: eth0\n"+
				"\n"+
				"Slave Interface: eth0\n"+
				"MII Status: up\n"+
				"Speed: 1000 Mbps\n",
		))
	})
	bond, err := parseBondFile("/proc/net/bonding/bond0")
	if err != nil {
		t.Fatalf("parseBondFile: %v", err)
	}
	if bond.Name != "bond0" || bond.ActiveSlave != "eth0" {
		t.Errorf("parseBondFile should derive the bond name from the path and parse content, got %+v", bond)
	}
	if len(bond.Slaves) != 1 || bond.Slaves[0].SpeedMbps != 1000 {
		t.Errorf("the slave's speed should be parsed, got %+v", bond.Slaves)
	}
}

func TestShortModeAllBranches(t *testing.T) {
	cases := []struct {
		mode string
		want string
	}{
		{"IEEE 802.3ad Dynamic link aggregation", "802.3ad"},
		{"fault-tolerance (active-backup)", "active-backup"},
		{"load balancing (round-robin)", "balance-rr"},
		{"load balancing (xor)", "balance-xor"},
		{"fault-tolerance (broadcast)", "broadcast"},
		{"adaptive transmit load balancing", "balance-tlb"},
		{"adaptive load balancing", "balance-alb"},
		{"some unknown future mode", "some unknown future mode"},
	}
	for _, c := range cases {
		if got := shortMode(c.mode); got != c.want {
			t.Errorf("shortMode(%q) = %q, want %q", c.mode, got, c.want)
		}
	}
}
