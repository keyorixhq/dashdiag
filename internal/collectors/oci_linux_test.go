//go:build linux

package collectors

import "testing"

func TestIsOCIGuest(t *testing.T) {
	cases := []struct {
		name            string
		chassisAssetTag string
		want            bool
	}{
		{"real OCI tag", "OracleCloud.com", true},
		{"trailing whitespace", "OracleCloud.com\n", true},
		{"case variance", "oraclecloud.com", true},
		{"empty", "", false},
		{"aws not oci", "Amazon EC2", false},
		{"generic qemu chassis", "", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := isOCIGuest(tc.chassisAssetTag); got != tc.want {
				t.Errorf("isOCIGuest(%q) = %v, want %v", tc.chassisAssetTag, got, tc.want)
			}
		})
	}
}

// parseVirtioRingCounters must read the aggregate rx_drops/tx_tx_timeouts
// counters and NOT double-count by also summing the per-queue rxN_drops/
// txN_tx_timeouts siblings virtio_net exposes alongside them (verified live on
// a single-queue A1.Flex shape that the aggregate and per-queue-0 values are
// the same counter).
func TestParseVirtioRingCounters(t *testing.T) {
	// Real `ethtool -S` output shape (single-queue A1.Flex, values live-verified).
	out := `NIC statistics:
     rx_drops: 5
     rx_xdp_packets: 0
     rx_xdp_tx: 0
     rx_xdp_redirects: 0
     rx_xdp_drops: 3
     rx_kicks: 15
     tx_xdp_tx: 0
     tx_xdp_tx_drops: 0
     tx_kicks: 77949
     tx_tx_timeouts: 2
     rx0_drops: 5
     rx0_xdp_packets: 0
     rx0_xdp_tx: 0
     rx0_xdp_redirects: 0
     rx0_xdp_drops: 3
     rx0_kicks: 15
     tx0_xdp_tx: 0
     tx0_xdp_tx_drops: 0
     tx0_kicks: 77949
     tx0_tx_timeouts: 2
`
	rxDrops, txTimeouts := parseVirtioRingCounters(out)
	if rxDrops != 5 {
		t.Errorf("rxDrops = %d, want 5 (must read the aggregate rx_drops, not sum it with rx0_drops/rx_xdp_drops)", rxDrops)
	}
	if txTimeouts != 2 {
		t.Errorf("txTimeouts = %d, want 2 (must read the aggregate tx_tx_timeouts, not sum it with tx0_tx_timeouts)", txTimeouts)
	}
}

func TestParseVirtioRingCounters_AllZero(t *testing.T) {
	out := "NIC statistics:\n     rx_drops: 0\n     tx_tx_timeouts: 0\n     rx0_drops: 0\n     tx0_tx_timeouts: 0\n"
	rxDrops, txTimeouts := parseVirtioRingCounters(out)
	if rxDrops != 0 || txTimeouts != 0 {
		t.Errorf("all-zero input: got rxDrops=%d txTimeouts=%d, want 0/0", rxDrops, txTimeouts)
	}
}

func TestParseVirtioRingCounters_GarbledValueIgnored(t *testing.T) {
	// A non-numeric value must not be ingested (don't crash/panic on hostile tool output).
	out := "NIC statistics:\n     rx_drops: not-a-number\n     tx_tx_timeouts: 4\n"
	rxDrops, txTimeouts := parseVirtioRingCounters(out)
	if rxDrops != 0 {
		t.Errorf("garbled rx_drops should be skipped, got %d", rxDrops)
	}
	if txTimeouts != 4 {
		t.Errorf("txTimeouts = %d, want 4", txTimeouts)
	}
}

// TestOCITimeSyncConfigured mirrors TestAmazonTimeSyncConfigured_DHCPSourcedir:
// a chrony.conf that delegates to a sourcedir must still be found, and OCI's
// own metadata NTP server (169.254.169.254) must be recognized there.
func TestOCITimeSyncConfigured(t *testing.T) {
	fake := fakeFSSource{
		files: map[string]string{
			"/etc/chrony.conf":          "sourcedir /run/chrony.d\npool 2.pool.ntp.org iburst\n",
			"/run/chrony.d/oci.sources": "server 169.254.169.254 iburst\n",
		},
		globs: map[string][]string{
			"/run/chrony.d/*.sources": {"/run/chrony.d/oci.sources"},
		},
	}
	defer SetSource(SetSource(fake))

	checked, configured := ociTimeSyncConfigured()
	if !checked {
		t.Fatal("a readable chrony.conf must mark the check as performed")
	}
	if !configured {
		t.Fatal("169.254.169.254 in a sourcedir-delegated file must be detected")
	}
}

func TestOCITimeSyncConfigured_NotPointed(t *testing.T) {
	fake := fakeFSSource{
		files: map[string]string{
			"/etc/chrony.conf": "pool 2.pool.ntp.org iburst\n",
		},
	}
	defer SetSource(SetSource(fake))

	checked, configured := ociTimeSyncConfigured()
	if !checked {
		t.Fatal("a readable chrony.conf must mark the check as performed")
	}
	if configured {
		t.Fatal("no OCI metadata NTP server present must NOT report configured=true")
	}
}
