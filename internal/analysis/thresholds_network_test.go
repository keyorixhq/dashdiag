package analysis

import "testing"

// Shared single source of truth for `dsd net` and `dsd health` on gateway packet
// loss, DNS latency, and TIME_WAIT sockets. Pinning the boundaries keeps both
// consumers in agreement (BUG-050 class) and documents the chosen granularity:
// packet loss comes from 2-3 pings (10/50 fits), DNS is continuous ms (100/500),
// TIME_WAIT gained the CRIT tier health previously lacked.
func TestNetworkLevelBoundaries(t *testing.T) {
	cases := []struct {
		name string
		got  string
		want string
	}{
		{"loss 9 ok", GatewayPacketLossLevel(9), ""},
		{"loss 10 warn", GatewayPacketLossLevel(10), "WARN"},
		{"loss 49 warn", GatewayPacketLossLevel(49), "WARN"},
		{"loss 50 crit", GatewayPacketLossLevel(50), "CRIT"},

		{"dns 99 ok", DNSResolveLevel(99), ""},
		{"dns 100 warn", DNSResolveLevel(100), "WARN"},
		{"dns 499 warn", DNSResolveLevel(499), "WARN"},
		{"dns 500 crit", DNSResolveLevel(500), "CRIT"},

		{"tw 999 ok", TimeWaitLevel(999), ""},
		{"tw 1000 warn", TimeWaitLevel(1000), "WARN"},
		{"tw 4999 warn", TimeWaitLevel(4999), "WARN"},
		{"tw 5000 crit", TimeWaitLevel(5000), "CRIT"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if c.got != c.want {
				t.Errorf("%s = %q, want %q", c.name, c.got, c.want)
			}
		})
	}
}
