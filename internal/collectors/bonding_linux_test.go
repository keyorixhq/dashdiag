//go:build linux

package collectors

import (
	"testing"
)

// Captured output from a real bond in 802.3ad mode with one slave down.
const bondFileActive = `Ethernet Channel Bonding Driver: v5.15

Bonding Mode: IEEE 802.3ad Dynamic link aggregation
Transmit Hash Policy: layer2 (0)
MII Status: up
MII Polling Interval (ms): 100
Up Delay (ms): 0
Down Delay (ms): 0

802.3ad info
LACP rate: slow
Min links: 0
Aggregator selection policy (ad_select): stable
System priority: 65535
System MAC address: 00:11:22:33:44:55
Active Aggregator Info:
	Aggregator ID: 1
	Number of ports: 2
	Actor Key: 17
	Partner Key: 17
	Partner Mac Address: 00:aa:bb:cc:dd:ee

Slave Interface: eth0
MII Status: up
Speed: 1000 Mbps
Duplex: full
Link Failure Count: 0
Permanent HW addr: 00:11:22:33:44:55
Slave queue ID: 0
Aggregator ID: 1

Slave Interface: eth1
MII Status: down
Speed: Unknown
Duplex: Unknown
Link Failure Count: 3
Permanent HW addr: 00:11:22:33:44:66
Slave queue ID: 0
Aggregator ID: 1
`

const bondFileActiveBackup = `Ethernet Channel Bonding Driver: v5.15

Bonding Mode: fault-tolerance (active-backup)
Primary Slave: eth0
Currently Active Slave: eth0
MII Status: up
MII Polling Interval (ms): 100

Slave Interface: eth0
MII Status: up
Speed: 1000 Mbps
Duplex: full
Link Failure Count: 0
Permanent HW addr: 00:11:22:33:44:55

Slave Interface: eth1
MII Status: up
Speed: 1000 Mbps
Duplex: full
Link Failure Count: 0
Permanent HW addr: 00:11:22:33:44:66
`

func TestParseBondFile(t *testing.T) {
	t.Run("802.3ad with one slave down", func(t *testing.T) {
		bond, err := parseBondFileContent("bond0", bondFileActive)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if bond.Name != "bond0" {
			t.Errorf("name = %q, want bond0", bond.Name)
		}
		if bond.ModeShort != "802.3ad" {
			t.Errorf("mode = %q, want 802.3ad", bond.ModeShort)
		}
		if len(bond.Slaves) != 2 {
			t.Fatalf("slaves = %d, want 2", len(bond.Slaves))
		}
		if bond.Slaves[0].State != "up" {
			t.Errorf("slave[0].state = %q, want up", bond.Slaves[0].State)
		}
		if bond.Slaves[1].State != "down" {
			t.Errorf("slave[1].state = %q, want down", bond.Slaves[1].State)
		}
		if bond.Slaves[1].LinkFails != 3 {
			t.Errorf("slave[1].LinkFails = %d, want 3", bond.Slaves[1].LinkFails)
		}
		if bond.DownSlaves != 1 {
			t.Errorf("DownSlaves = %d, want 1", bond.DownSlaves)
		}
	})

	t.Run("active-backup all slaves up", func(t *testing.T) {
		bond, err := parseBondFileContent("bond0", bondFileActiveBackup)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if bond.ModeShort != "active-backup" {
			t.Errorf("mode = %q, want active-backup", bond.ModeShort)
		}
		if bond.ActiveSlave != "eth0" {
			t.Errorf("active slave = %q, want eth0", bond.ActiveSlave)
		}
		if bond.DownSlaves != 0 {
			t.Errorf("DownSlaves = %d, want 0", bond.DownSlaves)
		}
	})
}

func TestShortMode(t *testing.T) {
	cases := []struct{ in, want string }{
		{"IEEE 802.3ad Dynamic link aggregation", "802.3ad"},
		{"fault-tolerance (active-backup)", "active-backup"},
		{"load balancing (round-robin)", "balance-rr"},
		{"broadcast", "broadcast"},
	}
	for _, c := range cases {
		got := shortMode(c.in)
		if got != c.want {
			t.Errorf("shortMode(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}
