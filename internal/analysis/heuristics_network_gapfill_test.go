package analysis

import (
	"testing"

	"github.com/keyorixhq/dashdiag/internal/models"
)

// Fills branch gaps in heuristics_network.go: checkBIND's ZonesFailed listing,
// deepTCPCounterInsights' WARN/INFO split for all three counters, checkNetwork's
// USB-bond-slave INFO / primary-USB-interface WARN branches, checkBonding's
// LACP-not-aggregating cause branches and USB-slave-on-healthy-bond INFO, and the
// pure isZeroMACHeuristic helper.

func TestCheckBIND_ZonesFailed(t *testing.T) {
	t.Parallel()
	b := models.BINDInfo{
		Detected: true, ServiceActive: true, ConfigOK: true,
		ZonesFailed: 2,
		Zones: []models.BINDZone{
			{Name: "example.com", OK: false},
			{Name: "example.org", OK: false},
			{Name: "good.example.com", OK: true},
		},
	}
	out := checkBIND(b)
	if !hasInsightMsg(out, "CRIT", "2 zone file(s) failed validation: example.com, example.org") {
		t.Errorf("failed zones must be CRIT and list the failing zone names, got %+v", out)
	}
}

func TestDeepTCPCounterInsights_SynRetransWarn(t *testing.T) {
	t.Parallel()
	// Above floor (100) with a high enough rate to hit WARN (>=60/hr): 1000 count
	// over a short uptime gives a high rate.
	net := models.NetworkInfo{SynRetransCount: 1000, UptimeSec: 3600}
	out := deepTCPCounterInsights(net)
	if !hasInsightMsg(out, "WARN", "SYN retransmissions/hr since boot") {
		t.Errorf("high sustained SYN retrans rate must WARN, got %+v", out)
	}
}

func TestDeepTCPCounterInsights_SynRetransInfo(t *testing.T) {
	t.Parallel()
	// Above floor but low rate (long uptime dilutes it below 60/hr) → INFO.
	net := models.NetworkInfo{SynRetransCount: 200, UptimeSec: 30 * 24 * 3600}
	out := deepTCPCounterInsights(net)
	if !hasInsightMsg(out, "INFO", "SYN retransmissions since boot") {
		t.Errorf("low sustained SYN retrans rate must INFO, got %+v", out)
	}
}

func TestDeepTCPCounterInsights_ListenOverflowCrit(t *testing.T) {
	t.Parallel()
	net := models.NetworkInfo{ListenOverflows: 1000, UptimeSec: 3600}
	out := deepTCPCounterInsights(net)
	if !hasInsightMsg(out, "CRIT", "listen queue overflowing") {
		t.Errorf("sustained saturating listen overflow rate must CRIT, got %+v", out)
	}
}

func TestDeepTCPCounterInsights_ListenOverflowWarn(t *testing.T) {
	t.Parallel()
	net := models.NetworkInfo{ListenOverflows: 5, UptimeSec: 3600}
	out := deepTCPCounterInsights(net)
	if !hasInsightMsg(out, "WARN", "listen-queue overflow(s) since boot") {
		t.Errorf("moderate listen overflow rate must WARN, got %+v", out)
	}
}

func TestDeepTCPCounterInsights_ListenOverflowInfo(t *testing.T) {
	t.Parallel()
	net := models.NetworkInfo{ListenOverflows: 2, UptimeSec: 30 * 24 * 3600}
	out := deepTCPCounterInsights(net)
	if !hasInsightMsg(out, "INFO", "listen-queue overflow(s) since boot") {
		t.Errorf("low-rate historical listen overflow must INFO, got %+v", out)
	}
}

func TestDeepTCPCounterInsights_RetransFailWarn(t *testing.T) {
	t.Parallel()
	net := models.NetworkInfo{RetransFailCount: 100, UptimeSec: 3600}
	out := deepTCPCounterInsights(net)
	if !hasInsightMsg(out, "WARN", "TCP retransmit failures/hr since boot") {
		t.Errorf("sustained retrans-fail rate must WARN, got %+v", out)
	}
}

func TestDeepTCPCounterInsights_RetransFailInfo(t *testing.T) {
	t.Parallel()
	net := models.NetworkInfo{RetransFailCount: 20, UptimeSec: 30 * 24 * 3600}
	out := deepTCPCounterInsights(net)
	if !hasInsightMsg(out, "INFO", "TCP retransmit failures since boot") {
		t.Errorf("low retrans-fail rate must INFO, got %+v", out)
	}
}

func TestCheckNetwork_PrimaryInterfaceUSB(t *testing.T) {
	t.Parallel()
	net := models.NetworkInfo{
		PrimaryInterface: "eth0",
		Interfaces: []models.InterfaceInfo{
			{Name: "eth0", IsUSB: true, Driver: "r8152", SpeedMbps: 1000},
		},
	}
	out := checkNetwork(net)
	if !hasInsightMsg(out, "WARN", "primary interface eth0 is USB-attached (r8152 @ 1Gbps)") {
		t.Errorf("USB primary interface at >=1000Mbps must WARN with Gbps speed, got %+v", out)
	}
}

func TestCheckNetwork_PrimaryInterfaceUSBSubGbps(t *testing.T) {
	t.Parallel()
	net := models.NetworkInfo{
		PrimaryInterface: "eth0",
		Interfaces: []models.InterfaceInfo{
			{Name: "eth0", IsUSB: true, SpeedMbps: 100},
		},
	}
	out := checkNetwork(net)
	if !hasInsightMsg(out, "WARN", "primary interface eth0 is USB-attached (USB NIC @ 100Mbps)") {
		t.Errorf("USB primary interface under 1000Mbps must WARN with Mbps speed and fallback driver label, got %+v", out)
	}
}

func TestCheckBonding_LACPNotAggregatingZeroMAC(t *testing.T) {
	t.Parallel()
	b := models.BondingInfo{Bonds: []models.BondInterface{
		{Name: "bond0", Slaves: []models.BondSlave{{Name: "eth0"}, {Name: "eth1"}}, NotAggregating: true, PartnerMAC: "00:00:00:00:00:00"},
	}}
	out := checkBonding(b)
	if !hasInsightMsg(out, "WARN", "the switch ports are not configured in a matching LACP port-channel") {
		t.Errorf("zero partner MAC must attribute cause to switch-side config, got %+v", out)
	}
}

func TestCheckBonding_LACPNotAggregatingNonZeroMAC(t *testing.T) {
	t.Parallel()
	b := models.BondingInfo{Bonds: []models.BondInterface{
		{Name: "bond0", Slaves: []models.BondSlave{{Name: "eth0"}, {Name: "eth1"}}, NotAggregating: true, PartnerMAC: "aa:bb:cc:dd:ee:ff"},
	}}
	out := checkBonding(b)
	if !hasInsightMsg(out, "WARN", "some links failed to join the active aggregator") {
		t.Errorf("non-zero partner MAC must attribute cause to a partial join, got %+v", out)
	}
}

func TestIsZeroMACHeuristic(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name string
		mac  string
		want bool
	}{
		{"empty string", "", false},
		{"all zero", "00:00:00:00:00:00", true},
		{"whitespace padded all zero", "  00:00:00:00:00:00  ", true},
		{"non-zero mac", "aa:bb:cc:dd:ee:ff", false},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := isZeroMACHeuristic(tt.mac); got != tt.want {
				t.Errorf("isZeroMACHeuristic(%q) = %v, want %v", tt.mac, got, tt.want)
			}
		})
	}
}
