//go:build linux

package collectors

import (
	"encoding/binary"
	"os"
	"testing"

	"github.com/keyorixhq/dashdiag/internal/source"
)

// fakeFSSource serves scripted file/glob results for the time-sync detection
// tests. Only ReadFile and Glob are exercised; the rest of the interface is left
// nil (a call would panic, flagging an unexpected access).
type fakeFSSource struct {
	source.Source
	files map[string]string
	globs map[string][]string
}

func (f fakeFSSource) ReadFile(path string) ([]byte, error) {
	if body, ok := f.files[path]; ok {
		return []byte(body), nil
	}
	return nil, os.ErrNotExist
}

func (f fakeFSSource) Glob(pattern string) ([]string, error) { return f.globs[pattern], nil }

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

func TestIsEBSModel(t *testing.T) {
	// The documented Amazon NVMe model strings — EBS is matched, instance-store is
	// excluded (its 0xD0 read would be fail-safe via the magic guard anyway, but the
	// filter keeps us off it). Covers the instance-store-exclusion path the t4g
	// validation box can't exercise (it has only EBS volumes).
	cases := []struct {
		model string
		want  bool
	}{
		{"Amazon Elastic Block Store", true},
		{"amazon elastic block store", true}, // case-insensitive
		{"Amazon EC2 NVMe Instance Storage", false},
		{"Samsung SSD 970 EVO", false},
		{"", false},
	}
	for _, c := range cases {
		if got := isEBSModel(c.model); got != c.want {
			t.Errorf("isEBSModel(%q)=%v want %v", c.model, got, c.want)
		}
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

func TestENASRDActive(t *testing.T) {
	// ENA Express enabled and carrying traffic → SRD packet counters non-zero.
	const active = "     tx_pkts: 1000\n     ena_srd_tx_pkts: 42\n     ena_srd_rx_pkts: 7\n"
	if !enaSRDActive(active) {
		t.Error("non-zero ena_srd_*_pkts should report ENA Express active")
	}
	// SRD counters present but zero (enabled, no eligible traffic yet) → not active.
	const idle = "     ena_srd_tx_pkts: 0\n     ena_srd_rx_pkts: 0\n"
	if enaSRDActive(idle) {
		t.Error("zero SRD counters should NOT report active")
	}
	// No SRD counters at all (ENA Express not enabled) → not active.
	if enaSRDActive("     tx_pkts: 1000\n     rx_pkts: 900\n") {
		t.Error("absent SRD counters should NOT report active")
	}
	// Garbled value must not be ingested.
	if enaSRDActive("     ena_srd_tx_pkts: not-a-number\n") {
		t.Error("garbled SRD value should NOT report active")
	}
}

// TestAmazonTimeSyncConfigured_DHCPSourcedir reproduces the Amazon Linux 2023
// layout (validated live on a t4g.micro, 2026-06-24): chrony.conf delegates to
// `sourcedir /run/chrony.d`, where the DHCP client drops the Amazon Time Sync
// server (169.254.169.123) — it never appears under /etc. The old detector only
// grepped /etc/chrony.conf + /etc/chrony/conf.d and false-reported "NTP is not
// pointed at the Amazon Time Sync Service" on the default EC2 distro.
func TestAmazonTimeSyncConfigured_DHCPSourcedir(t *testing.T) {
	fake := fakeFSSource{
		files: map[string]string{
			"/etc/chrony.conf":                      "sourcedir /run/chrony.d\nsourcedir /etc/chrony.d\npool 2.amazon.pool.ntp.org iburst\n",
			"/run/chrony.d/link-local-ipv4.sources": "server 169.254.169.123 prefer iburst minpoll 4 maxpoll 4\n",
		},
		globs: map[string][]string{
			"/run/chrony.d/*.sources": {"/run/chrony.d/link-local-ipv4.sources"},
		},
	}
	defer SetSource(SetSource(fake))

	checked, uses := amazonTimeSyncConfigured()
	if !checked {
		t.Fatal("a readable chrony.conf must mark the check as performed")
	}
	if !uses {
		t.Fatal("Amazon Time Sync server in a sourcedir-delegated /run/chrony.d file must be detected (AL2023 DHCP layout) — was a false-negative")
	}
}

// TestAmazonTimeSyncConfigured_NotPointed: a host with chrony but no Amazon Time
// Sync server anywhere (incl. delegated sourcedirs) must report checked-but-not-using,
// not a false positive.
func TestAmazonTimeSyncConfigured_NotPointed(t *testing.T) {
	fake := fakeFSSource{
		files: map[string]string{
			"/etc/chrony.conf":              "sourcedir /run/chrony.d\npool 2.pool.ntp.org iburst\n",
			"/run/chrony.d/generic.sources": "server 10.0.0.1 iburst\n",
		},
		globs: map[string][]string{
			"/run/chrony.d/*.sources": {"/run/chrony.d/generic.sources"},
		},
	}
	defer SetSource(SetSource(fake))

	checked, uses := amazonTimeSyncConfigured()
	if !checked {
		t.Fatal("a readable chrony.conf must mark the check as performed")
	}
	if uses {
		t.Fatal("no Amazon Time Sync server present must NOT report uses=true")
	}
}
