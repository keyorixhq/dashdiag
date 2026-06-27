//go:build linux

package collectors

import (
	"os"
	"path/filepath"
	"testing"
)

func TestIsKVMGuest(t *testing.T) {
	cases := []struct {
		vendor, product string
		want            bool
	}{
		{"QEMU", "Standard PC (i440FX + PIIX, 1996)", true}, // Proxmox (verified live)
		{"QEMU", "", true},
		{"Red Hat", "KVM", true},  // RHV/oVirt product signature
		{"Amazon EC2", "", false}, // cloud KVM — has its own collector, must NOT match
		{"Google", "Google Compute Engine", false},
		{"Microsoft Corporation", "Virtual Machine", false},
		{"VMware, Inc.", "VMware7,1", false},
		{"", "", false},
	}
	for _, c := range cases {
		if got := isKVMGuest(c.vendor, c.product); got != c.want {
			t.Errorf("isKVMGuest(%q,%q) = %v, want %v", c.vendor, c.product, got, c.want)
		}
	}
}

func TestKVMNICEmulated(t *testing.T) {
	for _, d := range []string{"e1000", "e1000e", "rtl8139", "8139cp", "8139too", "ne2k_pci", "pcnet32", "E1000"} {
		if !kvmNICEmulated(d) {
			t.Errorf("kvmNICEmulated(%q) = false, want true (emulated)", d)
		}
	}
	for _, d := range []string{"virtio_net", "mlx5_core", "ena", "ixgbevf", ""} {
		if kvmNICEmulated(d) {
			t.Errorf("kvmNICEmulated(%q) = true, want false (paravirtual/passthrough)", d)
		}
	}
}

func TestCumulativeStealPct(t *testing.T) {
	// Verbatim /proc/stat aggregate line from the real Proxmox guest (VM 101):
	// steal=578 of ~61.3M total → ~0.0009%.
	const healthy = "cpu  33271 478 25440 60994282 289066 0 2277 578 0 0\n" +
		"cpu0 16635 239 12720 30497141 144533 0 1138 289 0 0\n"
	if got := cumulativeStealPct(healthy); got < 0.0008 || got > 0.0011 {
		t.Errorf("cumulativeStealPct(healthy) = %v, want ~0.00094", got)
	}
	// steal=100 of total 1000 (100+100+700+100) → 10%.
	if got := cumulativeStealPct("cpu  100 0 100 700 0 0 0 100 0 0\n"); got < 9.9 || got > 10.1 {
		t.Errorf("cumulativeStealPct(overcommit) = %v, want ~10", got)
	}
	// Per-core line only (no aggregate) and empty → 0, not a panic.
	if got := cumulativeStealPct("cpu0 1 2 3 4 5 6 7 8 9 10\n"); got != 0 {
		t.Errorf("cumulativeStealPct(no aggregate) = %v, want 0", got)
	}
	if got := cumulativeStealPct(""); got != 0 {
		t.Errorf("cumulativeStealPct(empty) = %v, want 0", got)
	}
}

func TestCollectKVMDiskBuses(t *testing.T) {
	root := t.TempDir()
	// vd*/hd* are classified by name; sd* by the controller in their sysfs symlink
	// target (virtio → virtio-scsi, ata → sata, neither → legacy LSI scsi). The sda
	// target mirrors the real Proxmox path: ".../virtio1/host0/.../block/sda".
	mkDir := func(name string) {
		if err := os.Mkdir(filepath.Join(root, name), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	mkLink := func(name, target string) {
		if err := os.Symlink(target, filepath.Join(root, name)); err != nil {
			t.Fatal(err)
		}
	}
	mkLink("sda", "../devices/pci0000:00/0000:00:05.0/virtio1/host0/target0:0:0/0:0:0:0/block/sda")
	mkLink("sdb", "../devices/pci0000:00/0000:00:1f.2/ata1/host0/target0:0:0/0:0:0:0/block/sdb")
	mkLink("sdc", "../devices/pci0000:00/0000:00:10.0/host0/target0:0:0/0:0:0:0/block/sdc")
	mkDir("vda")
	mkDir("hda")
	mkDir("sr0") // cdrom — skipped

	buses, emulated := collectKVMDiskBuses(root)

	want := map[string]string{"sda": "virtio-scsi", "sdb": "sata", "sdc": "scsi", "vda": "virtio-blk", "hda": "ide"}
	for dev, w := range want {
		if buses[dev] != w {
			t.Errorf("bus[%s] = %q, want %q", dev, buses[dev], w)
		}
	}
	if _, ok := buses["sr0"]; ok {
		t.Error("sr0 (cdrom) must be skipped")
	}
	// Emulated = ide/sata/scsi; virtio-blk/virtio-scsi excluded.
	wantEmu := map[string]bool{"hda": true, "sdb": true, "sdc": true}
	if len(emulated) != len(wantEmu) {
		t.Fatalf("emulated = %v, want %v", emulated, wantEmu)
	}
	for _, d := range emulated {
		if !wantEmu[d] {
			t.Errorf("%q must not be in emulated (it's paravirtual)", d)
		}
	}
}

func TestCollectKVMDiskBusesMissingDir(t *testing.T) {
	buses, emulated := collectKVMDiskBuses(filepath.Join(t.TempDir(), "nope"))
	if buses != nil || emulated != nil {
		t.Errorf("missing block dir should yield nil/nil, got %v/%v", buses, emulated)
	}
}
