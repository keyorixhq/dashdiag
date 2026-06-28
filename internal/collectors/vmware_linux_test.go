//go:build linux

package collectors

import (
	"os"
	"path/filepath"
	"testing"
)

func TestIsVMwareGuest(t *testing.T) {
	cases := []struct {
		vendor, product string
		want            bool
	}{
		{"VMware, Inc.", "VMware Virtual Platform", true},
		{"VMware, Inc.", "VMware7,1", true},
		{"", "VMware20,1", true},
		{"QEMU", "Standard PC (Q35 + ICH9, 2009)", false}, // KVM — must NOT match
		{"Microsoft Corporation", "Virtual Machine", false},
		{"Dell Inc.", "PowerEdge R740", false},
		{"", "", false},
	}
	for _, c := range cases {
		if got := isVMwareGuest(c.vendor, c.product); got != c.want {
			t.Errorf("isVMwareGuest(%q,%q) = %v, want %v", c.vendor, c.product, got, c.want)
		}
	}
}

func TestNICDriverEmulated(t *testing.T) {
	for _, d := range []string{"e1000", "e1000e", "vlance", "pcnet32", "E1000"} {
		if !nicDriverEmulated(d) {
			t.Errorf("nicDriverEmulated(%q) = false, want true (emulated)", d)
		}
	}
	for _, d := range []string{"vmxnet3", "ixgbevf", "mlx5_core", ""} {
		if nicDriverEmulated(d) {
			t.Errorf("nicDriverEmulated(%q) = true, want false (paravirtual/passthrough)", d)
		}
	}
}

func TestModuleLoaded(t *testing.T) {
	const procModules = "vmw_pvscsi 28672 3 - Live 0x0000000000000000\n" +
		"vmw_balloon 32768 0 - Live 0x0000000000000000\n" +
		"vmxnet3 65536 1 - Live 0x0000000000000000\n"
	if !moduleLoaded(procModules, "vmw_pvscsi") {
		t.Error("vmw_pvscsi should be detected as loaded")
	}
	if !moduleLoaded(procModules, "vmw_balloon") {
		t.Error("vmw_balloon should be detected as loaded")
	}
	if moduleLoaded(procModules, "vmw_pvsci") { // substring of a real name — must NOT match
		t.Error("partial name must not match (first-column exact match only)")
	}
	if moduleLoaded(procModules, "nvme") {
		t.Error("absent module must not match")
	}
	if moduleLoaded("", "vmw_pvscsi") {
		t.Error("empty /proc/modules must not match")
	}
}

func TestCollectNICDrivers(t *testing.T) {
	root := t.TempDir()
	// Build a fake /sys/class/net: ens160 emulated (e1000), ens192 paravirtual
	// (vmxnet3), lo (must be skipped), and "noiface" with no device/driver link.
	mk := func(iface, driver string) {
		dev := filepath.Join(root, iface, "device")
		if err := os.MkdirAll(dev, 0o755); err != nil {
			t.Fatal(err)
		}
		if driver != "" {
			// driver is a symlink; only its basename matters to the parser.
			target := filepath.Join("/sys/bus/pci/drivers", driver)
			if err := os.Symlink(target, filepath.Join(dev, "driver")); err != nil {
				t.Fatal(err)
			}
		}
	}
	mk("ens160", "e1000")
	mk("ens192", "vmxnet3")
	mk("noiface", "") // device dir but no driver link → skipped
	if err := os.MkdirAll(filepath.Join(root, "lo", "device"), 0o755); err != nil {
		t.Fatal(err)
	}
	os.Symlink("/sys/bus/pci/drivers/e1000", filepath.Join(root, "lo", "device", "driver")) //nolint:errcheck

	drivers, emulated := collectNICDrivers(root)

	if drivers["ens160"] != "e1000" || drivers["ens192"] != "vmxnet3" {
		t.Errorf("drivers = %v, want ens160=e1000 ens192=vmxnet3", drivers)
	}
	if _, ok := drivers["lo"]; ok {
		t.Error("loopback must be skipped")
	}
	if _, ok := drivers["noiface"]; ok {
		t.Error("iface without a driver link must be skipped")
	}
	if len(emulated) != 1 || emulated[0] != "ens160" {
		t.Errorf("emulated = %v, want [ens160] (vmxnet3 is paravirtual)", emulated)
	}
}

func TestCollectNICDriversMissingDir(t *testing.T) {
	drivers, emulated := collectNICDrivers(filepath.Join(t.TempDir(), "nope"))
	if drivers != nil || emulated != nil {
		t.Errorf("missing net dir should yield nil/nil, got %v/%v", drivers, emulated)
	}
}

func TestParseLeadingInt(t *testing.T) {
	cases := []struct {
		in   string
		want int
		ok   bool
	}{
		{"128 MB", 128, true},
		{"  1500 MHz\n", 1500, true},
		{"0 MB", 0, true},
		{"Unlimited", 0, false},
		{"", 0, false},
		{"MB 128", 0, false}, // integer must be at the start
	}
	for _, c := range cases {
		got, ok := parseLeadingInt(c.in)
		if got != c.want || ok != c.ok {
			t.Errorf("parseLeadingInt(%q) = (%d,%v), want (%d,%v)", c.in, got, ok, c.want, c.ok)
		}
	}
}

func TestCPUCountFromProc(t *testing.T) {
	// Two logical CPUs (real /proc/cpuinfo shape, trimmed).
	cpuinfo := "processor\t: 0\nmodel name\t: Xeon\n\nprocessor\t: 1\nmodel name\t: Xeon\n"
	if got := cpuCountFromProc(cpuinfo); got != 2 {
		t.Errorf("cpuCountFromProc = %d, want 2", got)
	}
	if got := cpuCountFromProc(""); got != 0 {
		t.Errorf("cpuCountFromProc(empty) = %d, want 0", got)
	}
}

func TestMemTotalMBFromProc(t *testing.T) {
	// Real /proc/meminfo MemTotal line (kB → MB). 1965940 kB ≈ 1919 MB.
	meminfo := "MemTotal:        1965940 kB\nMemFree:          257000 kB\n"
	if got := memTotalMBFromProc(meminfo); got != 1919 {
		t.Errorf("memTotalMBFromProc = %d, want 1919", got)
	}
	if got := memTotalMBFromProc("MemFree: 100 kB"); got != 0 {
		t.Errorf("memTotalMBFromProc(no MemTotal) = %d, want 0", got)
	}
}

func TestCollectSCSITimeouts(t *testing.T) {
	root := t.TempDir()
	// sda below the recommendation, sdb compliant, vda (virtio-blk) must be
	// ignored, sdc with an unreadable timeout must be skipped (not flagged).
	mk := func(dev, timeout string) {
		dir := filepath.Join(root, dev, "device")
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Fatal(err)
		}
		if timeout != "" {
			if err := os.WriteFile(filepath.Join(dir, "timeout"), []byte(timeout), 0o644); err != nil {
				t.Fatal(err)
			}
		}
	}
	mk("sda", "30\n")
	mk("sdb", "180\n")
	mk("vda", "30\n") // virtio-blk — not SCSI, must be ignored
	mk("sdc", "")     // no timeout file — skipped

	timeouts, low := collectSCSITimeouts(root)

	if timeouts["sda"] != 30 || timeouts["sdb"] != 180 {
		t.Errorf("timeouts = %v, want sda=30 sdb=180", timeouts)
	}
	if _, ok := timeouts["vda"]; ok {
		t.Error("virtio-blk (vda) must not be scanned")
	}
	if _, ok := timeouts["sdc"]; ok {
		t.Error("disk with no timeout file must be skipped")
	}
	if len(low) != 1 || low[0] != "sda" {
		t.Errorf("low = %v, want [sda] (sdb is compliant at 180s)", low)
	}
}

func TestCollectVMwareDiskIDs(t *testing.T) {
	root := t.TempDir()
	// Mirrors the real tenant: IDE/SATA disks (sda/sde) carry a wwid; the pvscsi
	// "Virtual disk" disks (sdb/sdc/sdd) have an EMPTY wwid — the disk.EnableUUID=
	// FALSE signature. nvme0n1 / vda must be ignored (not sd*).
	mk := func(dev, wwid string, hasFile bool) {
		dir := filepath.Join(root, dev, "device")
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Fatal(err)
		}
		if hasFile {
			if err := os.WriteFile(filepath.Join(dir, "wwid"), []byte(wwid), 0o644); err != nil {
				t.Fatal(err)
			}
		}
	}
	mk("sda", "naa.5000c29cfc4431c4\n", true) // SATA — has ID
	mk("sde", "naa.5000c292640bd534\n", true) // SATA — has ID
	// sdb/sdc/sdd model the three real EnableUUID=FALSE manifestations, all → flagged:
	// empty file, no file, and (on real vSphere, 192.168.30.231) a present-but-ENXIO
	// read — readFileTrimmedLocal collapses all three to "" by design (see the
	// collector comment: a read error IS the no-page-0x83 signal, not a gap to skip).
	mk("sdb", "", true)               // pvscsi — empty wwid file (EnableUUID off)
	mk("sdc", "", false)              // pvscsi — no wwid file at all (≡ the ENXIO read-error case)
	mk("sdd", "", true)               // pvscsi boot disk — empty wwid
	mk("nvme0n1", "eui.469d\n", true) // NVMe — must be ignored (not sd*)

	checked, noID := collectVMwareDiskIDs(root)

	if !checked {
		t.Error("checked = false, want true (sd* disks present)")
	}
	want := []string{"sdb", "sdc", "sdd"}
	if len(noID) != len(want) {
		t.Fatalf("noStableID = %v, want %v", noID, want)
	}
	for i, w := range want {
		if noID[i] != w {
			t.Errorf("noStableID[%d] = %q, want %q (sorted)", i, noID[i], w)
		}
	}
	for _, d := range noID {
		if d == "sda" || d == "sde" || d == "nvme0n1" {
			t.Errorf("%q has an ID (or isn't SCSI) and must not be flagged", d)
		}
	}
}

func TestCollectVMwareDiskIDsNVMeOnly(t *testing.T) {
	// An NVMe-only guest has no sd* disks → checked=false → no EnableUUID finding
	// (the flag is irrelevant without SCSI disks).
	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, "nvme0n1", "device"), 0o755); err != nil {
		t.Fatal(err)
	}
	checked, noID := collectVMwareDiskIDs(root)
	if checked || noID != nil {
		t.Errorf("NVMe-only: got checked=%v noID=%v, want false/nil", checked, noID)
	}
}

func TestParseVMXNETStats(t *testing.T) {
	// Verbatim slice of `ethtool -S ens160` (vmxnet3) from the real tenant, with
	// the counts altered to non-zero so the parser's field mapping is exercised.
	const out = `NIC statistics:
       TSO pkts tx: 307
       ucast pkts tx: 998733
       pkts tx err: 0
       pkts tx discard: 0
       drv dropped tx total: 0
          hdr err: 0
       ring full: 7
       LRO pkts rx: 116401
       pkts rx OOB: 3
       pkts rx err: 0
       drv dropped rx total: 0
          err: 0
       rx buf alloc fail: 11
          xdp drops: 0`
	s := parseVMXNETStats(out)
	if s.RxBufAllocFail != 11 {
		t.Errorf("RxBufAllocFail = %d, want 11", s.RxBufAllocFail)
	}
	if s.RxOOB != 3 {
		t.Errorf("RxOOB = %d, want 3", s.RxOOB)
	}
	if s.TxRingFull != 7 {
		t.Errorf("TxRingFull = %d, want 7 (the 'ring full' line)", s.TxRingFull)
	}

	// Healthy (all zero) → all fields zero.
	zero := parseVMXNETStats("       rx buf alloc fail: 0\n       ring full: 0\n       pkts rx OOB: 0\n")
	if zero.RxBufAllocFail != 0 || zero.TxRingFull != 0 || zero.RxOOB != 0 {
		t.Errorf("all-zero parse should be zero, got %+v", zero)
	}
}

func TestCollectSCSITimeoutsMissingDir(t *testing.T) {
	timeouts, low := collectSCSITimeouts(filepath.Join(t.TempDir(), "nope"))
	if timeouts != nil || low != nil {
		t.Errorf("missing block dir should yield nil/nil, got %v/%v", timeouts, low)
	}
}
