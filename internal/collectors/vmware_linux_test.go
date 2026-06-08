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

func TestCollectSCSITimeoutsMissingDir(t *testing.T) {
	timeouts, low := collectSCSITimeouts(filepath.Join(t.TempDir(), "nope"))
	if timeouts != nil || low != nil {
		t.Errorf("missing block dir should yield nil/nil, got %v/%v", timeouts, low)
	}
}
