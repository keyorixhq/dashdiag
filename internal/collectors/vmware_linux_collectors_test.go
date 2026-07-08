//go:build linux

package collectors

import (
	"context"
	"testing"
	"time"

	"github.com/keyorixhq/dashdiag/internal/models"
	"github.com/keyorixhq/dashdiag/internal/source"
)

// withVMwareFixture needs both dimensions the shared withCombinedFixture (see
// security_linux_source_test.go) provides: lookPath("vmtoolsd"/
// "vmware-toolbox-cmd") goes through Cached, and collectNICDrivers resolves
// /sys/class/net/<if>/device/driver symlinks via Readlink.
func withVMwareFixture(t *testing.T, cached map[string][]byte, links map[string]string, seed func(b *source.Bundle)) {
	t.Helper()
	withCombinedFixture(t, cached, links, seed)
}

func TestVMwareCollectorIdentity(t *testing.T) {
	c := NewVMwareCollector()
	if c == nil {
		t.Fatal("NewVMwareCollector returned nil")
	}
	if c.Name() != "VMware" {
		t.Errorf("Name() = %q, want VMware", c.Name())
	}
	if c.Timeout() != 8*time.Second {
		t.Errorf("Timeout() = %v, want 8s", c.Timeout())
	}
}

// TestVMwareCollector_Collect_FullHappyPath exercises the entire Collect()
// pipeline: tools installed+running, one vmxnet3 NIC with ethtool stats, both
// SCSI-timeout and disk-ID checks, and the full vmware-toolbox-cmd stat chain.
func TestVMwareCollector_Collect_FullHappyPath(t *testing.T) {
	withVMwareFixture(t,
		map[string][]byte{
			"lookpath/vmtoolsd":           []byte("/usr/bin/vmtoolsd"),
			"lookpath/vmware-toolbox-cmd": []byte("/usr/bin/vmware-toolbox-cmd"),
		},
		map[string]string{
			"/sys/class/net/ens160/device/driver": "/sys/bus/pci/drivers/vmxnet3",
		},
		func(b *source.Bundle) {
			b.PutFile("/sys/class/dmi/id/product_name", []byte("VMware7,1\n"))

			// vmwareToolsRunning -> procCommRunning("vmtoolsd") scans /proc.
			b.PutDir("/proc", []string{"100"})
			b.PutDir("/proc/100", []string{"comm", "cgroup"})
			b.PutFile("/proc/100/comm", []byte("vmtoolsd\n"))
			// /proc/100/cgroup intentionally unseeded: unreadable -> host, not container.

			// collectNICDrivers.
			b.PutDir("/sys/class/net", []string{"ens160"})

			// modules.
			b.PutFile("/proc/modules", []byte("vmw_pvscsi 28672 3 - Live 0x0\nvmw_balloon 32768 0 - Live 0x0\n"))

			// collectSCSITimeouts + collectVMwareDiskIDs share /sys/block.
			b.PutDir("/sys/block", []string{"sda"})
			b.PutFile("/sys/block/sda/device/timeout", []byte("30\n"))
			b.PutFile("/sys/block/sda/device/wwid", []byte("")) // EnableUUID=FALSE signature

			// collectVMXNETStats.
			b.PutCmd("ethtool", []string{"-S", "ens160"}, "       rx buf alloc fail: 2\n       pkts rx OOB: 1\n       ring full: 3\n", 0)
			b.PutFile("/sys/class/net/ens160/statistics/rx_packets", []byte("1000\n"))
			b.PutFile("/sys/class/net/ens160/statistics/tx_packets", []byte("2000\n"))

			// collectVMwareStat via vmware-toolbox-cmd stat <key>.
			b.PutCmd("/usr/bin/vmware-toolbox-cmd", []string{"stat", "balloon"}, "128 MB\n", 0)
			b.PutCmd("/usr/bin/vmware-toolbox-cmd", []string{"stat", "swap"}, "64 MB\n", 0)
			b.PutCmd("/usr/bin/vmware-toolbox-cmd", []string{"stat", "memlimit"}, "3000 MB\n", 0)
			b.PutCmd("/usr/bin/vmware-toolbox-cmd", []string{"stat", "cpulimit"}, "Unlimited\n", 0)
			b.PutCmd("/usr/bin/vmware-toolbox-cmd", []string{"stat", "speed"}, "2600 MHz\n", 0)
			b.PutFile("/proc/cpuinfo", []byte("processor\t: 0\nmodel name\t: Xeon\n\nprocessor\t: 1\nmodel name\t: Xeon\n"))
			b.PutFile("/proc/meminfo", []byte("MemTotal:        2097152 kB\nMemFree:          100 kB\n"))
		},
	)

	c := NewVMwareCollector()
	raw, err := c.Collect(context.Background())
	if err != nil {
		t.Fatalf("Collect() error: %v", err)
	}
	info := raw.(*models.VMwareInfo)

	if info.ProductName != "VMware7,1" {
		t.Errorf("ProductName = %q, want VMware7,1", info.ProductName)
	}
	if !info.ToolsInstalled {
		t.Error("ToolsInstalled = false, want true")
	}
	if !info.ToolsRunning {
		t.Error("ToolsRunning = false, want true")
	}
	if info.NICDrivers["ens160"] != "vmxnet3" {
		t.Errorf("NICDrivers = %v, want ens160=vmxnet3", info.NICDrivers)
	}
	if len(info.EmulatedNICs) != 0 {
		t.Errorf("EmulatedNICs = %v, want none (vmxnet3 is paravirtual)", info.EmulatedNICs)
	}
	if !info.PVSCSILoaded || !info.BalloonLoaded {
		t.Errorf("PVSCSILoaded=%v BalloonLoaded=%v, want both true", info.PVSCSILoaded, info.BalloonLoaded)
	}
	if !info.SCSIDisksChecked || len(info.SCSITimeouts) != 1 || info.SCSITimeouts["sda"] != 30 {
		t.Errorf("SCSI timeouts = checked=%v %v, want checked=true sda=30", info.SCSIDisksChecked, info.SCSITimeouts)
	}
	if len(info.LowSCSITimeouts) != 1 || info.LowSCSITimeouts[0] != "sda" {
		t.Errorf("LowSCSITimeouts = %v, want [sda] (30s < 180s)", info.LowSCSITimeouts)
	}
	if len(info.DisksNoStableID) != 1 || info.DisksNoStableID[0] != "sda" {
		t.Errorf("DisksNoStableID = %v, want [sda] (empty wwid)", info.DisksNoStableID)
	}
	if len(info.VMXNETStats) != 1 {
		t.Fatalf("VMXNETStats = %v, want 1 entry", info.VMXNETStats)
	}
	vs := info.VMXNETStats[0]
	if vs.Iface != "ens160" || vs.RxBufAllocFail != 2 || vs.RxOOB != 1 || vs.TxRingFull != 3 ||
		vs.RxPackets != 1000 || vs.TxPackets != 2000 {
		t.Errorf("VMXNETStats[0] = %+v, want ens160/2/1/3/1000/2000", vs)
	}
	if !info.StatAvailable {
		t.Fatal("StatAvailable = false, want true")
	}
	if info.BalloonMB != 128 || info.HostSwapMB != 64 {
		t.Errorf("BalloonMB=%d HostSwapMB=%d, want 128/64", info.BalloonMB, info.HostSwapMB)
	}
	if info.MemLimitMB != 3000 {
		t.Errorf("MemLimitMB = %d, want 3000", info.MemLimitMB)
	}
	if info.CPULimitMHz != 0 {
		t.Errorf("CPULimitMHz = %d, want 0 (Unlimited)", info.CPULimitMHz)
	}
	if info.HostMHzPerCPU != 2600 {
		t.Errorf("HostMHzPerCPU = %d, want 2600", info.HostMHzPerCPU)
	}
	if info.NumVCPU != 2 {
		t.Errorf("NumVCPU = %d, want 2", info.NumVCPU)
	}
	if info.TotalRAMMB != 2048 {
		t.Errorf("TotalRAMMB = %d, want 2048", info.TotalRAMMB)
	}
}

// TestVMwareCollector_Collect_ToolsNotRunning verifies collectVMwareStat is
// skipped entirely (StatAvailable stays false, no toolbox-cmd RPCs) when the
// tools daemon is not running — the gate at the end of Collect().
func TestVMwareCollector_Collect_ToolsNotRunning(t *testing.T) {
	withVMwareFixture(t, nil, nil, func(b *source.Bundle) {
		b.PutFile("/sys/class/dmi/id/product_name", []byte("VMware7,1\n"))
		b.PutDir("/proc", []string{}) // no vmtoolsd process
		b.PutDir("/sys/class/net", []string{})
		b.PutFile("/proc/modules", []byte(""))
		b.PutDir("/sys/block", []string{})
		b.PutCmdNotFound("systemctl", []string{"is-active", "vmtoolsd"})
		b.PutCmdNotFound("systemctl", []string{"is-active", "open-vm-tools"})
	})

	c := NewVMwareCollector()
	raw, err := c.Collect(context.Background())
	if err != nil {
		t.Fatalf("Collect() error: %v", err)
	}
	info := raw.(*models.VMwareInfo)
	if info.ToolsRunning {
		t.Error("ToolsRunning = true, want false")
	}
	if info.StatAvailable {
		t.Error("StatAvailable = true, want false (collectVMwareStat must be skipped)")
	}
}

func TestCollectVMXNETStats_EthtoolMissing(t *testing.T) {
	withFixtureSource(t, func(b *source.Bundle) {
		b.PutCmdNotFound("ethtool", []string{"-S", "ens160"})
	})
	out := collectVMXNETStats(context.Background(), map[string]string{"ens160": "vmxnet3"}, "/sys/class/net")
	if out != nil {
		t.Errorf("collectVMXNETStats = %v, want nil when ethtool is absent", out)
	}
}

func TestCollectVMXNETStats_SkipsNonVMXNET3(t *testing.T) {
	out := collectVMXNETStats(context.Background(), map[string]string{"ens160": "e1000"}, "/sys/class/net")
	if out != nil {
		t.Errorf("collectVMXNETStats = %v, want nil for non-vmxnet3 driver", out)
	}
}

func TestReadCounterFile(t *testing.T) {
	withFixtureSource(t, func(b *source.Bundle) {
		b.PutFile("/sys/class/net/eth0/statistics/rx_packets", []byte("12345\n"))
		b.PutFile("/sys/class/net/eth0/statistics/bad", []byte("not-a-number\n"))
	})
	if got := readCounterFile("/sys/class/net/eth0/statistics/rx_packets"); got != 12345 {
		t.Errorf("readCounterFile = %d, want 12345", got)
	}
	if got := readCounterFile("/sys/class/net/eth0/statistics/bad"); got != 0 {
		t.Errorf("readCounterFile(non-numeric) = %d, want 0", got)
	}
	if got := readCounterFile("/sys/class/net/eth0/statistics/missing"); got != 0 {
		t.Errorf("readCounterFile(missing) = %d, want 0", got)
	}
}

func TestVmwareToolboxPath_LookPathFound(t *testing.T) {
	withVMwareFixture(t, map[string][]byte{"lookpath/vmware-toolbox-cmd": []byte("/usr/bin/vmware-toolbox-cmd")}, nil, nil)
	if got := vmwareToolboxPath(); got != "/usr/bin/vmware-toolbox-cmd" {
		t.Errorf("vmwareToolboxPath() = %q, want /usr/bin/vmware-toolbox-cmd", got)
	}
}

func TestVmwareToolboxPath_FallbackFileExists(t *testing.T) {
	withFixtureSource(t, func(b *source.Bundle) {
		// lookPath unseeded -> Cached returns ErrNotRecorded -> falls to hardcoded paths.
		b.PutStat("/usr/bin/vmware-toolbox-cmd", source.FileMeta{})
	})
	if got := vmwareToolboxPath(); got != "/usr/bin/vmware-toolbox-cmd" {
		t.Errorf("vmwareToolboxPath() = %q, want /usr/bin/vmware-toolbox-cmd (fallback)", got)
	}
}

func TestVmwareToolboxPath_NotFound(t *testing.T) {
	withFixtureSource(t, func(b *source.Bundle) {})
	if got := vmwareToolboxPath(); got != "" {
		t.Errorf("vmwareToolboxPath() = %q, want empty", got)
	}
}

func TestVmwareStatMB(t *testing.T) {
	withFixtureSource(t, func(b *source.Bundle) {
		b.PutCmd("/usr/bin/vmware-toolbox-cmd", []string{"stat", "balloon"}, "256 MB\n", 0)
		b.PutCmd("/usr/bin/vmware-toolbox-cmd", []string{"stat", "bogus"}, "", 1)
	})
	if got, ok := vmwareStatMB(context.Background(), "/usr/bin/vmware-toolbox-cmd", "balloon"); !ok || got != 256 {
		t.Errorf("vmwareStatMB(balloon) = (%d,%v), want (256,true)", got, ok)
	}
	if _, ok := vmwareStatMB(context.Background(), "/usr/bin/vmware-toolbox-cmd", "bogus"); ok {
		t.Error("vmwareStatMB(bogus) ok = true, want false (command failed)")
	}
}

func TestVmwareStatLimit(t *testing.T) {
	withFixtureSource(t, func(b *source.Bundle) {
		b.PutCmd("/usr/bin/vmware-toolbox-cmd", []string{"stat", "memlimit"}, "4096 MB\n", 0)
		b.PutCmd("/usr/bin/vmware-toolbox-cmd", []string{"stat", "cpulimit"}, "Unlimited\n", 0)
		b.PutCmd("/usr/bin/vmware-toolbox-cmd", []string{"stat", "fails"}, "", 1)
		b.PutCmd("/usr/bin/vmware-toolbox-cmd", []string{"stat", "garbage"}, "not-a-number\n", 0)
	})
	if got, limited := vmwareStatLimit(context.Background(), "/usr/bin/vmware-toolbox-cmd", "memlimit"); !limited || got != 4096 {
		t.Errorf("vmwareStatLimit(memlimit) = (%d,%v), want (4096,true)", got, limited)
	}
	if got, limited := vmwareStatLimit(context.Background(), "/usr/bin/vmware-toolbox-cmd", "cpulimit"); limited || got != 0 {
		t.Errorf("vmwareStatLimit(cpulimit=Unlimited) = (%d,%v), want (0,false)", got, limited)
	}
	if _, limited := vmwareStatLimit(context.Background(), "/usr/bin/vmware-toolbox-cmd", "fails"); limited {
		t.Error("vmwareStatLimit(fails) limited = true, want false")
	}
	if _, limited := vmwareStatLimit(context.Background(), "/usr/bin/vmware-toolbox-cmd", "garbage"); limited {
		t.Error("vmwareStatLimit(garbage) limited = true, want false (no leading int)")
	}
}

func TestCollectVMwareStat_NoToolbox(t *testing.T) {
	withFixtureSource(t, func(b *source.Bundle) {})
	info := &models.VMwareInfo{}
	collectVMwareStat(context.Background(), info)
	if info.StatAvailable {
		t.Error("StatAvailable = true, want false when toolbox-cmd is absent")
	}
}

func TestCollectVMwareStat_BalloonFails(t *testing.T) {
	withVMwareFixture(t, map[string][]byte{"lookpath/vmware-toolbox-cmd": []byte("/usr/bin/vmware-toolbox-cmd")}, nil, func(b *source.Bundle) {
		b.PutCmd("/usr/bin/vmware-toolbox-cmd", []string{"stat", "balloon"}, "", 1)
	})
	info := &models.VMwareInfo{}
	collectVMwareStat(context.Background(), info)
	if info.StatAvailable {
		t.Error("StatAvailable = true, want false when the balloon probe fails")
	}
}

func TestVmwareToolsInstalled_LookPathFound(t *testing.T) {
	withVMwareFixture(t, map[string][]byte{"lookpath/vmtoolsd": []byte("/usr/bin/vmtoolsd")}, nil, nil)
	if !vmwareToolsInstalled() {
		t.Error("vmwareToolsInstalled() = false, want true")
	}
}

func TestVmwareToolsInstalled_FallbackFileExists(t *testing.T) {
	withFixtureSource(t, func(b *source.Bundle) {
		b.PutStat("/usr/sbin/vmtoolsd", source.FileMeta{})
	})
	if !vmwareToolsInstalled() {
		t.Error("vmwareToolsInstalled() = false, want true (fallback path exists)")
	}
}

func TestVmwareToolsInstalled_NotFound(t *testing.T) {
	withFixtureSource(t, func(b *source.Bundle) {})
	if vmwareToolsInstalled() {
		t.Error("vmwareToolsInstalled() = true, want false")
	}
}

func TestVmwareToolsRunning_ProcCommFound(t *testing.T) {
	withFixtureSource(t, func(b *source.Bundle) {
		b.PutDir("/proc", []string{"55"})
		b.PutDir("/proc/55", []string{"comm"})
		b.PutFile("/proc/55/comm", []byte("vmtoolsd\n"))
	})
	if !vmwareToolsRunning(context.Background()) {
		t.Error("vmwareToolsRunning() = false, want true")
	}
}

func TestVmwareToolsRunning_SystemctlFallback(t *testing.T) {
	withFixtureSource(t, func(b *source.Bundle) {
		// /proc unreadable -> procCommRunning returns ok=false -> systemctl fallback.
		b.PutCmd("systemctl", []string{"is-active", "vmtoolsd"}, "active\n", 0)
	})
	if !vmwareToolsRunning(context.Background()) {
		t.Error("vmwareToolsRunning() = false, want true (systemctl fallback)")
	}
}

func TestVmwareToolsRunning_NotRunning(t *testing.T) {
	withFixtureSource(t, func(b *source.Bundle) {
		b.PutDir("/proc", []string{})
		b.PutCmd("systemctl", []string{"is-active", "vmtoolsd"}, "inactive\n", 3)
		b.PutCmd("systemctl", []string{"is-active", "open-vm-tools"}, "inactive\n", 3)
	})
	if vmwareToolsRunning(context.Background()) {
		t.Error("vmwareToolsRunning() = true, want false")
	}
}

func TestKernelModulePresent(t *testing.T) {
	const mods = "vmw_pvscsi 28672 3 - Live 0x0\n"
	if !kernelModulePresent(mods, "vmw_pvscsi") {
		t.Error("kernelModulePresent(loaded) = false, want true")
	}
	withFixtureSource(t, func(b *source.Bundle) {
		b.PutStat("/sys/module/vmw_balloon", source.FileMeta{})
	})
	if !kernelModulePresent(mods, "vmw_balloon") {
		t.Error("kernelModulePresent(built-in) = false, want true (present under /sys/module)")
	}
	withFixtureSource(t, func(b *source.Bundle) {})
	if kernelModulePresent(mods, "nvme") {
		t.Error("kernelModulePresent(absent) = true, want false")
	}
}
