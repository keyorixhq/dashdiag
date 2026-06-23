//go:build linux

package collectors

import (
	"encoding/binary"
	"testing"
)

func TestIsAWSGuest(t *testing.T) {
	cases := []struct {
		name                                   string
		sysVendor, biosVendor, product, hvUUID string
		want                                   bool
	}{
		{"nitro sys_vendor", "Amazon EC2", "Amazon EC2", "t4g.small", "", true},
		{"bios vendor only", "", "Amazon EC2", "", "", true},
		{"xen hypervisor uuid", "Xen", "Xen", "HVM domU", "ec2a1b2c-...", true},
		{"vmware not aws", "VMware, Inc.", "Phoenix", "VMware7,1", "564d...", false},
		{"bare metal", "Dell Inc.", "Dell", "PowerEdge R740", "", false},
		{"empty", "", "", "", "", false},
	}
	for _, c := range cases {
		if got := isAWSGuest(c.sysVendor, c.biosVendor, c.product, c.hvUUID); got != c.want {
			t.Errorf("%s: isAWSGuest=%v want %v", c.name, got, c.want)
		}
	}
}

// realistic `ethtool -S ens5` output on an ENA interface — header, per-queue stats,
// and the five allowance-exceeded counters interleaved with unrelated lines.
const enaEthtoolOutput = `NIC statistics:
     rx_packets: 123456
     tx_packets: 654321
     rx_bytes: 99999999
     tx_bytes: 88888888
     queue_0_tx_cnt: 1000
     queue_0_rx_cnt: 2000
     bw_in_allowance_exceeded: 0
     bw_out_allowance_exceeded: 42
     pps_allowance_exceeded: 0
     conntrack_allowance_exceeded: 7
     linklocal_allowance_exceeded: 0
     missing_tx_completion: 0
`

func TestParseENAStats(t *testing.T) {
	got := parseENAStats(enaEthtoolOutput)
	want := map[string]uint64{"bw_in": 0, "bw_out": 42, "pps": 0, "conntrack": 7, "linklocal": 0}
	if len(got) != len(want) {
		t.Fatalf("parsed %d counters, want %d: %v", len(got), len(want), got)
	}
	for k, v := range want {
		if got[k] != v {
			t.Errorf("counter %s = %d, want %d", k, got[k], v)
		}
	}
}

func TestParseENAStats_GarbledValueSkipped(t *testing.T) {
	// A non-numeric value must be skipped, not ingested as a bogus reading.
	got := parseENAStats("NIC statistics:\n     pps_allowance_exceeded: N/A\n     bw_in_allowance_exceeded: 3\n")
	if _, ok := got["pps"]; ok {
		t.Errorf("garbled pps value must be skipped, got %v", got)
	}
	if got["bw_in"] != 3 {
		t.Errorf("bw_in = %d, want 3", got["bw_in"])
	}
}

// makeEBSLogPage builds a valid EBS stats log page with the given exceeded counters.
func makeEBSLogPage(magic uint32, volIOPS, volTP, instIOPS, instTP uint64) []byte {
	buf := make([]byte, 4096)
	binary.LittleEndian.PutUint32(buf[0:4], magic)
	binary.LittleEndian.PutUint64(buf[56:64], volIOPS)
	binary.LittleEndian.PutUint64(buf[64:72], volTP)
	binary.LittleEndian.PutUint64(buf[72:80], instIOPS)
	binary.LittleEndian.PutUint64(buf[80:88], instTP)
	return buf
}

func TestParseEBSLogPage_Valid(t *testing.T) {
	buf := makeEBSLogPage(ebsStatsMagic, 111, 222, 333, 444)
	got, ok := parseEBSLogPage(buf)
	if !ok {
		t.Fatal("valid EBS log page rejected")
	}
	if got.volIOPS != 111 || got.volTP != 222 || got.instIOPS != 333 || got.instTP != 444 {
		t.Errorf("parsed %+v, want {111 222 333 444}", got)
	}
}

func TestParseEBSLogPage_RejectsBadMagic(t *testing.T) {
	// Wrong magic (e.g. a non-EBS device's log page) must NOT be ingested as a real
	// all-zero reading — that would be a false-OK.
	buf := makeEBSLogPage(0xDEADBEEF, 5, 5, 5, 5)
	if _, ok := parseEBSLogPage(buf); ok {
		t.Error("log page without the EBS magic must be rejected")
	}
}

func TestParseEBSLogPage_RejectsShort(t *testing.T) {
	buf := makeEBSLogPage(ebsStatsMagic, 1, 1, 1, 1)[:40] // truncated below the counters
	if _, ok := parseEBSLogPage(buf); ok {
		t.Error("short buffer must be rejected")
	}
}

func TestSubSat(t *testing.T) {
	if subSat(10, 4) != 6 {
		t.Error("10-4 should be 6")
	}
	if subSat(4, 10) != 0 {
		t.Error("underflow must saturate to 0 (counter reset mid-window)")
	}
}
