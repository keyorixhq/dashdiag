//go:build linux

package collectors

import (
	"testing"

	"github.com/keyorixhq/dashdiag/internal/models"
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

// Real capture (Debian 13, kernel 6.12) of a NEGOTIATED 802.3ad bond: both slaves up,
// both in the same aggregator (ID 1), a non-zero LACP partner MAC. The kernel prints the
// "Active Aggregator Info" block with Partner Mac Address + Number of ports when an
// aggregator is selected. This must NOT be flagged as not-aggregating.
const bondFileLACPNegotiated = `Ethernet Channel Bonding Driver: v6.12.90+deb13.1-cloud-amd64

Bonding Mode: IEEE 802.3ad Dynamic link aggregation
Transmit Hash Policy: layer2 (0)
MII Status: up
MII Polling Interval (ms): 100
Up Delay (ms): 0
Down Delay (ms): 0
Peer Notification Delay (ms): 0

802.3ad info
LACP active: on
LACP rate: fast
Min links: 0
Aggregator selection policy (ad_select): stable
Active Aggregator Info:
	Aggregator ID: 1
	Number of ports: 2
	Actor Key: 15
	Partner Key: 15
	Partner Mac Address: 9a:b7:ad:28:22:15

Slave Interface: veth0a
MII Status: up
Speed: 10000 Mbps
Duplex: full
Link Failure Count: 0
Permanent HW addr: f6:6f:c4:c7:43:30
Slave queue ID: 0
Aggregator ID: 1
Actor Churn State: none
Partner Churn State: none

Slave Interface: veth1a
MII Status: up
Speed: 10000 Mbps
Duplex: full
Link Failure Count: 0
Permanent HW addr: aa:3d:87:ae:c1:b4
Slave queue ID: 0
Aggregator ID: 1
Actor Churn State: none
Partner Churn State: none
`

// Real capture of the FALSE-OK: an 802.3ad bond whose slaves are both MII-"up" but LACP
// never negotiated (the peer stopped speaking LACP). Both links stay up, so an MII-only
// check reads healthy — yet the slaves landed in DIFFERENT aggregators (1 and 2) and the
// LACP partner MAC is all-zero, so the bond carries no traffic and has no redundancy.
// This kernel omits the top-level "Active Aggregator Info" block when nothing is
// aggregating, so the per-slave Aggregator ID mismatch is the signal.
const bondFileLACPNotAggregating = `Ethernet Channel Bonding Driver: v6.12.90+deb13.1-cloud-amd64

Bonding Mode: IEEE 802.3ad Dynamic link aggregation
Transmit Hash Policy: layer2 (0)
MII Status: up
MII Polling Interval (ms): 100
Up Delay (ms): 0
Down Delay (ms): 0
Peer Notification Delay (ms): 0

802.3ad info
LACP active: on
LACP rate: fast
Min links: 0
Aggregator selection policy (ad_select): stable

Slave Interface: veth0a
MII Status: up
Speed: 10000 Mbps
Duplex: full
Link Failure Count: 0
Permanent HW addr: f6:6f:c4:c7:43:30
Slave queue ID: 0
Aggregator ID: 1
Actor Churn State: none
Partner Churn State: churned
details partner lacp pdu:
    system priority: 65535
    system mac address: 00:00:00:00:00:00
    port state: 0

Slave Interface: veth1a
MII Status: up
Speed: 10000 Mbps
Duplex: full
Link Failure Count: 1
Permanent HW addr: aa:3d:87:ae:c1:b4
Slave queue ID: 0
Aggregator ID: 2
Actor Churn State: monitoring
Partner Churn State: monitoring
details partner lacp pdu:
    system priority: 65535
    system mac address: 00:00:00:00:00:00
    port state: 0
`

// Older-kernel format: a single "Active Aggregator Info" block carries Partner Mac
// Address + Number of ports. Both slaves are MII-up and in aggregator 1, but the partner
// MAC is all-zero (no partner heard) and only 1 port is in the aggregator while 2 slaves
// are up. Exercises the zero-partner-MAC + partial-aggregator signals.
const bondFileLACPZeroPartner = `Ethernet Channel Bonding Driver: v5.15

Bonding Mode: IEEE 802.3ad Dynamic link aggregation
MII Status: up
MII Polling Interval (ms): 100

802.3ad info
LACP rate: slow
Active Aggregator Info:
	Aggregator ID: 1
	Number of ports: 1
	Partner Mac Address: 00:00:00:00:00:00

Slave Interface: eth0
MII Status: up
Speed: 1000 Mbps
Duplex: full
Link Failure Count: 0
Aggregator ID: 1

Slave Interface: eth1
MII Status: up
Speed: 1000 Mbps
Duplex: full
Link Failure Count: 0
Aggregator ID: 1
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
		// Verdict booleans are now derived in the shared parser (so the standalone
		// BondingCollector's JSON gets them too, not just the NetworkCollector path).
		if !bond.Degraded {
			t.Error("Degraded = false, want true (one slave down)")
		}
		if bond.AllDown {
			t.Error("AllDown = true, want false (only one of two slaves down)")
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

	t.Run("802.3ad negotiated — not flagged", func(t *testing.T) {
		bond, err := parseBondFileContent("bond0", bondFileLACPNegotiated)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if bond.DownSlaves != 0 || bond.Degraded {
			t.Errorf("DownSlaves=%d Degraded=%v, want 0/false", bond.DownSlaves, bond.Degraded)
		}
		if bond.PartnerMAC != "9a:b7:ad:28:22:15" {
			t.Errorf("PartnerMAC = %q, want 9a:b7:ad:28:22:15", bond.PartnerMAC)
		}
		if bond.AggregatorPorts != 2 {
			t.Errorf("AggregatorPorts = %d, want 2", bond.AggregatorPorts)
		}
		if bond.Slaves[0].AggregatorID != 1 || bond.Slaves[1].AggregatorID != 1 {
			t.Errorf("aggregator IDs = %d/%d, want 1/1", bond.Slaves[0].AggregatorID, bond.Slaves[1].AggregatorID)
		}
		if bond.NotAggregating {
			t.Error("NotAggregating = true, want false (bond is fully negotiated)")
		}
	})

	t.Run("802.3ad MII-up but not aggregating — aggregator mismatch", func(t *testing.T) {
		bond, err := parseBondFileContent("bond0", bondFileLACPNotAggregating)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		// The false-OK precondition: every slave is MII-up, so the MII/Degraded checks
		// see nothing wrong.
		if bond.DownSlaves != 0 || bond.Degraded || bond.AllDown {
			t.Fatalf("DownSlaves=%d Degraded=%v AllDown=%v, want 0/false/false — the bond LOOKS healthy by MII",
				bond.DownSlaves, bond.Degraded, bond.AllDown)
		}
		if bond.Slaves[0].AggregatorID != 1 || bond.Slaves[1].AggregatorID != 2 {
			t.Errorf("aggregator IDs = %d/%d, want 1/2 (split = not aggregating)",
				bond.Slaves[0].AggregatorID, bond.Slaves[1].AggregatorID)
		}
		if !bond.NotAggregating {
			t.Error("NotAggregating = false, want true (slaves MII-up but in different aggregators)")
		}
	})

	t.Run("802.3ad zero partner MAC + partial aggregator", func(t *testing.T) {
		bond, err := parseBondFileContent("bond0", bondFileLACPZeroPartner)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if bond.DownSlaves != 0 {
			t.Fatalf("DownSlaves = %d, want 0 (both MII-up)", bond.DownSlaves)
		}
		if bond.PartnerMAC != "00:00:00:00:00:00" {
			t.Errorf("PartnerMAC = %q, want 00:00:00:00:00:00", bond.PartnerMAC)
		}
		if !bond.NotAggregating {
			t.Error("NotAggregating = false, want true (zero partner MAC = no LACP partner heard)")
		}
	})
}

func TestIsZeroMAC(t *testing.T) {
	cases := []struct {
		in   string
		want bool
	}{
		{"00:00:00:00:00:00", true},
		{"  00:00:00:00:00:00  ", true},
		{"", false}, // absent field is not a signal
		{"9a:b7:ad:28:22:15", false},
		{"00:aa:bb:cc:dd:ee", false},
		{"00:00:00:00:00:01", false},
	}
	for _, c := range cases {
		if got := isZeroMAC(c.in); got != c.want {
			t.Errorf("isZeroMAC(%q) = %v, want %v", c.in, got, c.want)
		}
	}
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

// TestLacpNotAggregating covers the LACP-not-bundling heuristic's boundary
// cases: non-802.3ad modes are always exempt, an all-down bond defers to the
// separate AllDown CRIT rather than double-flagging, a zero partner MAC means
// LACP never heard a partner, a shrunk active-aggregator port count means some
// up slaves fell out of the aggregation, and split aggregator IDs among the up
// slaves mean the slaves never converged onto one aggregator.
func TestLacpNotAggregating(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name string
		bond models.BondInterface
		want bool
	}{
		{
			name: "non-802.3ad mode is always exempt",
			bond: models.BondInterface{ModeShort: "active-backup", PartnerMAC: "00:00:00:00:00:00"},
			want: false,
		},
		{
			name: "all slaves down defers to AllDown, not double-flagged",
			bond: models.BondInterface{
				ModeShort:  "802.3ad",
				Slaves:     []models.BondSlave{{State: "down"}, {State: "down"}},
				DownSlaves: 2,
			},
			want: false,
		},
		{
			name: "zero partner MAC means LACP never heard a partner",
			bond: models.BondInterface{
				ModeShort:  "802.3ad",
				Slaves:     []models.BondSlave{{State: "up"}},
				PartnerMAC: "00:00:00:00:00:00",
			},
			want: true,
		},
		{
			name: "aggregator ports fewer than up slaves means some fell out",
			bond: models.BondInterface{
				ModeShort:       "802.3ad",
				Slaves:          []models.BondSlave{{State: "up"}, {State: "up"}},
				PartnerMAC:      "00:11:22:33:44:55",
				AggregatorPorts: 1,
			},
			want: true,
		},
		{
			name: "split aggregator IDs among up slaves means never converged",
			bond: models.BondInterface{
				ModeShort:  "802.3ad",
				PartnerMAC: "00:11:22:33:44:55",
				Slaves: []models.BondSlave{
					{State: "up", AggregatorID: 1},
					{State: "up", AggregatorID: 2},
				},
			},
			want: true,
		},
		{
			name: "healthy: single aggregator ID, full ports, real partner MAC",
			bond: models.BondInterface{
				ModeShort:       "802.3ad",
				PartnerMAC:      "00:11:22:33:44:55",
				AggregatorPorts: 2,
				Slaves: []models.BondSlave{
					{State: "up", AggregatorID: 1},
					{State: "up", AggregatorID: 1},
				},
			},
			want: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := lacpNotAggregating(tt.bond); got != tt.want {
				t.Errorf("lacpNotAggregating(%+v) = %v, want %v", tt.bond, got, tt.want)
			}
		})
	}
}
