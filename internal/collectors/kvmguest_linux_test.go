//go:build linux

package collectors

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/keyorixhq/dashdiag/internal/models"
	"github.com/keyorixhq/dashdiag/internal/source"
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

func TestKVMGuestCollectorIdentity(t *testing.T) {
	t.Parallel()
	c := NewKVMGuestCollector()
	if c.Name() != "KVMGuest" {
		t.Errorf("Name() = %q, want KVMGuest", c.Name())
	}
	if c.Timeout() != 5*time.Second {
		t.Errorf("Timeout() = %v, want 5s", c.Timeout())
	}
}

func TestKVMGuestAvailable(t *testing.T) {
	t.Run("QEMU sys_vendor", func(t *testing.T) {
		withFixtureSource(t, func(b *source.Bundle) {
			b.PutFile("/sys/class/dmi/id/sys_vendor", []byte("QEMU\n"))
			b.PutFile("/sys/class/dmi/id/product_name", []byte("Standard PC (i440FX + PIIX, 1996)\n"))
		})
		if !KVMGuestAvailable() {
			t.Error("expected true for QEMU sys_vendor")
		}
	})

	t.Run("cloud vendor excluded", func(t *testing.T) {
		withFixtureSource(t, func(b *source.Bundle) {
			b.PutFile("/sys/class/dmi/id/sys_vendor", []byte("Amazon EC2\n"))
			b.PutFile("/sys/class/dmi/id/product_name", []byte("\n"))
		})
		if KVMGuestAvailable() {
			t.Error("expected false for a cloud KVM guest (has its own collector)")
		}
	})

	t.Run("bare metal", func(t *testing.T) {
		withFixtureSource(t, func(_ *source.Bundle) {})
		if KVMGuestAvailable() {
			t.Error("expected false when no DMI files exist")
		}
	})
}

// TestKVMGuestCollector_Collect_HappyPath exercises the full Collect()
// pipeline: QGA channel+binary+running, one emulated NIC and one virtio NIC,
// virtio-blk + emulated SATA disk buses, balloon loaded, and non-zero steal.
func TestKVMGuestCollector_Collect_HappyPath(t *testing.T) {
	withCombinedFixture(t, nil,
		map[string]string{
			"/sys/class/net/eth0/device/driver": "/sys/bus/virtio/drivers/virtio_net",
			"/sys/class/net/eth1/device/driver": "/sys/bus/pci/drivers/e1000",
			"/sys/block/sda":                    "../../devices/pci0000:00/0000:00:05.0/virtio2/host0/target0:0:0/0:0:0:0/block/sda",
			"/sys/block/sdb":                    "../../devices/pci0000:00/0000:00:06.0/ata1/host1/target1:0:0/1:0:0:0/block/sdb",
		},
		func(b *source.Bundle) {
			b.PutFile("/sys/class/dmi/id/product_name", []byte("Standard PC (i440FX + PIIX, 1996)\n"))
			b.PutStat("/dev/virtio-ports/org.qemu.guest_agent.0", source.FileMeta{})
			b.PutStat("/usr/sbin/qemu-ga", source.FileMeta{})

			// kvmQGARunning -> procCommRunning("qemu-ga").
			b.PutDir("/proc", []string{"200"})
			b.PutDir("/proc/200", []string{"comm"})
			b.PutFile("/proc/200/comm", []byte("qemu-ga\n"))

			// collectNICDrivers.
			b.PutDir("/sys/class/net", []string{"eth0", "eth1", "lo"})

			// collectKVMDiskBuses.
			b.PutDir("/sys/block", []string{"sda", "sdb"})

			b.PutFile("/proc/modules", []byte("virtio_balloon 16384 0 - Live 0x0\n"))
			b.PutFile("/sys/devices/system/clocksource/clocksource0/current_clocksource", []byte("kvm-clock\n"))
			b.PutFile("/proc/stat", []byte(
				"cpu  100 0 100 700 0 0 0 100 0 0\ncpu0 50 0 50 350 0 0 0 50 0 0\n"))
		},
	)

	c := NewKVMGuestCollector()
	raw, err := c.Collect(context.Background())
	if err != nil {
		t.Fatalf("Collect() error: %v", err)
	}
	info := raw.(*models.KVMGuestInfo)

	if !info.IsGuest {
		t.Error("IsGuest = false, want true")
	}
	if info.ProductName != "Standard PC (i440FX + PIIX, 1996)" {
		t.Errorf("ProductName = %q, want the DMI product_name", info.ProductName)
	}
	if !info.QGAChannelPresent || !info.QGAInstalled || !info.QGARunning {
		t.Errorf("QGA flags = channel=%v installed=%v running=%v, want all true",
			info.QGAChannelPresent, info.QGAInstalled, info.QGARunning)
	}
	if info.NICDrivers["eth0"] != "virtio_net" || info.NICDrivers["eth1"] != "e1000" {
		t.Errorf("NICDrivers = %v, want eth0=virtio_net eth1=e1000", info.NICDrivers)
	}
	if len(info.EmulatedNICs) != 1 || info.EmulatedNICs[0] != "eth1" {
		t.Errorf("EmulatedNICs = %v, want [eth1]", info.EmulatedNICs)
	}
	if info.DiskBuses["sda"] != "virtio-scsi" || info.DiskBuses["sdb"] != "sata" {
		t.Errorf("DiskBuses = %v, want sda=virtio-scsi sdb=sata", info.DiskBuses)
	}
	if len(info.EmulatedDisks) != 1 || info.EmulatedDisks[0] != "sdb" {
		t.Errorf("EmulatedDisks = %v, want [sdb]", info.EmulatedDisks)
	}
	if !info.BalloonLoaded {
		t.Error("BalloonLoaded = false, want true")
	}
	if info.Clocksource != "kvm-clock" {
		t.Errorf("Clocksource = %q, want kvm-clock", info.Clocksource)
	}
	if info.StealPct <= 0 {
		t.Errorf("StealPct = %v, want > 0 (steal field=100 of total=1050)", info.StealPct)
	}
}

// TestKVMGuestCollector_Collect_Minimal guards the low-signal path: no QGA, no
// NICs, no disks, no balloon — Collect must still succeed with zero values,
// not error.
func TestKVMGuestCollector_Collect_Minimal(t *testing.T) {
	withCombinedFixture(t, nil, nil, func(b *source.Bundle) {
		b.PutFile("/sys/class/dmi/id/product_name", []byte("Standard PC\n"))
		b.PutDir("/proc", []string{})
		b.PutDir("/sys/class/net", []string{})
		b.PutDir("/sys/block", []string{})
		b.PutFile("/proc/modules", []byte(""))
		b.PutFile("/proc/stat", []byte("cpu  0 0 0 0 0 0 0 0 0 0\n"))
		b.PutCmdNotFound("systemctl", []string{"is-active", "qemu-guest-agent"})
	})

	c := NewKVMGuestCollector()
	raw, err := c.Collect(context.Background())
	if err != nil {
		t.Fatalf("Collect() error: %v", err)
	}
	info := raw.(*models.KVMGuestInfo)
	if info.QGAChannelPresent || info.QGAInstalled || info.QGARunning {
		t.Errorf("QGA flags should all be false, got channel=%v installed=%v running=%v",
			info.QGAChannelPresent, info.QGAInstalled, info.QGARunning)
	}
	if len(info.NICDrivers) != 0 || len(info.DiskBuses) != 0 {
		t.Errorf("expected no NICs/disks, got NICDrivers=%v DiskBuses=%v", info.NICDrivers, info.DiskBuses)
	}
	if info.BalloonLoaded {
		t.Error("BalloonLoaded = true, want false")
	}
	if info.StealPct != 0 {
		t.Errorf("StealPct = %v, want 0", info.StealPct)
	}
}

func TestKvmQGARunning(t *testing.T) {
	t.Run("proc comm match", func(t *testing.T) {
		withFixtureSource(t, func(b *source.Bundle) {
			b.PutDir("/proc", []string{"42"})
			b.PutDir("/proc/42", []string{"comm"})
			b.PutFile("/proc/42/comm", []byte("qemu-ga\n"))
		})
		if !kvmQGARunning(context.Background()) {
			t.Error("kvmQGARunning() = false, want true")
		}
	})

	t.Run("systemctl fallback active", func(t *testing.T) {
		withFixtureSource(t, func(b *source.Bundle) {
			// /proc unreadable -> procCommRunning ok=false -> systemctl fallback.
			b.PutCmd("systemctl", []string{"is-active", "qemu-guest-agent"}, "active\n", 0)
		})
		if !kvmQGARunning(context.Background()) {
			t.Error("kvmQGARunning() = false, want true (systemctl fallback)")
		}
	})

	t.Run("not running", func(t *testing.T) {
		withFixtureSource(t, func(b *source.Bundle) {
			b.PutDir("/proc", []string{})
			b.PutCmd("systemctl", []string{"is-active", "qemu-guest-agent"}, "inactive\n", 3)
		})
		if kvmQGARunning(context.Background()) {
			t.Error("kvmQGARunning() = true, want false")
		}
	})
}

// TestBuses2emptyNil is a pure-function test — safe to run in parallel.
func TestBuses2emptyNil(t *testing.T) {
	t.Parallel()
	if got := buses2emptyNil(nil); got != nil {
		t.Errorf("buses2emptyNil(nil) = %v, want nil", got)
	}
	if got := buses2emptyNil([]string{}); got != nil {
		t.Errorf("buses2emptyNil(empty) = %v, want nil", got)
	}
	if got := buses2emptyNil([]string{"sda"}); len(got) != 1 {
		t.Errorf("buses2emptyNil([sda]) = %v, want [sda]", got)
	}
}

// TestKvmDiskBus_ReadlinkErrorDefaultsToSCSI covers the readLink-error branch
// of kvmDiskBus not already exercised by TestCollectKVMDiskBuses (which only
// covers real symlinks via a tempdir): a fixture source with no seeded link
// for the sdX path must default to "scsi" (controller unknown, treated as
// emulated rather than silently OK).
func TestKvmDiskBus_ReadlinkErrorDefaultsToSCSI(t *testing.T) {
	withFixtureSource(t, func(_ *source.Bundle) {})
	if got := kvmDiskBus("sda", "/sys/block"); got != "scsi" {
		t.Errorf("kvmDiskBus(sda, unreadable link) = %q, want scsi", got)
	}
}

// TestKvmDiskBus_OtherPrefixReturnsEmpty covers devices that are neither
// vd*/hd*/sd* (nvme, loop, dm) — cdrom/loop/dm/nvme are not a guest disk-bus
// concern and must classify as "".
func TestKvmDiskBus_OtherPrefixReturnsEmpty(t *testing.T) {
	t.Parallel()
	if got := kvmDiskBus("nvme0n1", "/sys/block"); got != "" {
		t.Errorf("kvmDiskBus(nvme0n1) = %q, want empty", got)
	}
	if got := kvmDiskBus("loop0", "/sys/block"); got != "" {
		t.Errorf("kvmDiskBus(loop0) = %q, want empty", got)
	}
}
