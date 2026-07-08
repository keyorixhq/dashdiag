//go:build linux

package collectors

import (
	"context"
	"testing"
	"time"

	"github.com/keyorixhq/dashdiag/internal/models"
	"github.com/keyorixhq/dashdiag/internal/source"
)

// withAzureFixture needs the Cached dimension the shared withCombinedFixture
// (see security_linux_source_test.go) provides — lookPath("waagent") and
// imdsGet's "imds/<url>" cache key both go through Cached.
func withAzureFixture(t *testing.T, cached map[string][]byte, seed func(b *source.Bundle)) {
	t.Helper()
	withCombinedFixture(t, cached, nil, seed)
}

func TestAzureCollectorIdentity(t *testing.T) {
	c := NewAzureCollector()
	if c == nil {
		t.Fatal("NewAzureCollector returned nil")
	}
	if c.Name() != "Azure" {
		t.Errorf("Name() = %q, want Azure", c.Name())
	}
	if c.Timeout() != 3*time.Second {
		t.Errorf("Timeout() = %v, want 3s", c.Timeout())
	}
}

func TestAzureGuestAvailable_True(t *testing.T) {
	withFixtureSource(t, func(b *source.Bundle) {
		b.PutFile("/sys/class/dmi/id/sys_vendor", []byte("Microsoft Corporation\n"))
		b.PutFile("/sys/class/dmi/id/product_name", []byte("Virtual Machine\n"))
		b.PutFile("/sys/class/dmi/id/chassis_asset_tag", []byte("7783-7084-3265-9085-8269-3286-77\n"))
	})
	if !AzureGuestAvailable() {
		t.Error("AzureGuestAvailable() = false, want true")
	}
}

func TestAzureGuestAvailable_OnPremHyperV(t *testing.T) {
	withFixtureSource(t, func(b *source.Bundle) {
		b.PutFile("/sys/class/dmi/id/sys_vendor", []byte("Microsoft Corporation\n"))
		b.PutFile("/sys/class/dmi/id/product_name", []byte("Virtual Machine\n"))
		b.PutFile("/sys/class/dmi/id/chassis_asset_tag", []byte("\n"))
	})
	if AzureGuestAvailable() {
		t.Error("AzureGuestAvailable() = true, want false (on-prem Hyper-V, not Azure)")
	}
}

func TestAzureNVMeIOTimeout_NoNVMe(t *testing.T) {
	withFixtureSource(t, func(b *source.Bundle) {
		b.PutDir("/sys/class/nvme", []string{})
	})
	present, checked, secs := azureNVMeIOTimeout()
	if present || checked || secs != 0 {
		t.Errorf("azureNVMeIOTimeout() = (%v,%v,%d), want (false,false,0)", present, checked, secs)
	}
}

func TestAzureNVMeIOTimeout_PresentButUnreadable(t *testing.T) {
	withFixtureSource(t, func(b *source.Bundle) {
		b.PutDir("/sys/class/nvme", []string{"nvme0"})
	})
	present, checked, secs := azureNVMeIOTimeout()
	if !present || checked || secs != 0 {
		t.Errorf("azureNVMeIOTimeout() = (%v,%v,%d), want (true,false,0)", present, checked, secs)
	}
}

func TestAzureNVMeIOTimeout_Tuned(t *testing.T) {
	withFixtureSource(t, func(b *source.Bundle) {
		b.PutDir("/sys/class/nvme", []string{"nvme0"})
		b.PutFile("/sys/module/nvme_core/parameters/io_timeout", []byte("240\n"))
	})
	present, checked, secs := azureNVMeIOTimeout()
	if !present || !checked || secs != 240 {
		t.Errorf("azureNVMeIOTimeout() = (%v,%v,%d), want (true,true,240)", present, checked, secs)
	}
}

func TestAzureNVMeIOTimeout_GarbledValue(t *testing.T) {
	withFixtureSource(t, func(b *source.Bundle) {
		b.PutDir("/sys/class/nvme", []string{"nvme0"})
		b.PutFile("/sys/module/nvme_core/parameters/io_timeout", []byte("not-a-number\n"))
	})
	present, checked, secs := azureNVMeIOTimeout()
	if !present || checked || secs != 0 {
		t.Errorf("azureNVMeIOTimeout() = (%v,%v,%d), want (true,false,0)", present, checked, secs)
	}
}

func TestAzureDmesg_Success(t *testing.T) {
	withFixtureSource(t, func(b *source.Bundle) {
		b.PutCmd("dmesg", []string{}, "hv_balloon: Max. dynamic memory size: 8192 MB\n", 0)
	})
	if got := azureDmesg(context.Background()); got != "hv_balloon: Max. dynamic memory size: 8192 MB\n" {
		t.Errorf("azureDmesg() = %q, unexpected", got)
	}
}

func TestAzureDmesg_Restricted(t *testing.T) {
	withFixtureSource(t, func(b *source.Bundle) {
		b.PutCmd("dmesg", []string{}, "", 1)
	})
	if got := azureDmesg(context.Background()); got != "" {
		t.Errorf("azureDmesg() = %q, want empty on failure", got)
	}
}

func TestTempDiskStateFromHost(t *testing.T) {
	withFixtureSource(t, func(b *source.Bundle) {
		b.PutFile("/etc/waagent.conf", []byte("ResourceDisk.MountPoint=/mnt/resource\n"))
		b.PutFile("/proc/mounts", []byte("/dev/sdb1 /mnt/resource ext4 rw 0 0\n"))
		b.PutFile("/etc/fstab", []byte("/dev/sdb1 /mnt/resource/mysql-data ext4 defaults 0 0\n"))
	})
	present, device, mount, atRisk := tempDiskStateFromHost()
	if !present || device != "/dev/sdb1" || mount != "/mnt/resource" {
		t.Errorf("tempDiskStateFromHost() = (%v,%q,%q,_), unexpected", present, device, mount)
	}
	if !atRisk {
		t.Error("atRisk = false, want true (fstab mounts a subdir of the temp mount)")
	}
}

func TestTempDiskStateFromHost_Absent(t *testing.T) {
	withFixtureSource(t, func(b *source.Bundle) {})
	present, _, _, atRisk := tempDiskStateFromHost()
	if present || atRisk {
		t.Errorf("tempDiskStateFromHost() present=%v atRisk=%v, want both false", present, atRisk)
	}
}

const azureStorageProfileJSON = `{"osDisk":{"name":"osdisk1","caching":"ReadWrite"},"dataDisks":[{"name":"datadisk1","lun":"0","caching":"None"}]}`

func TestAzureDiskCaching_Success(t *testing.T) {
	withAzureFixture(t, map[string][]byte{
		"imds/http://169.254.169.254/metadata/instance/compute/storageProfile?api-version=2021-02-01&format=json": []byte(azureStorageProfileJSON),
	}, nil)
	checked, disks := azureDiskCaching(context.Background())
	if !checked {
		t.Fatal("checked = false, want true")
	}
	if len(disks) != 2 || disks[0].Name != "osdisk1" || !disks[0].IsOS || disks[1].Name != "datadisk1" || disks[1].Lun != 0 {
		t.Errorf("disks = %+v, unexpected", disks)
	}
}

func TestAzureDiskCaching_IMDSUnreachable(t *testing.T) {
	withAzureFixture(t, nil, nil)
	checked, disks := azureDiskCaching(context.Background())
	if checked || disks != nil {
		t.Errorf("azureDiskCaching() = (%v,%v), want (false,nil)", checked, disks)
	}
}

func TestWaagentState_InstalledAndRunning(t *testing.T) {
	withAzureFixture(t, map[string][]byte{"lookpath/waagent": []byte("/usr/sbin/waagent")}, func(b *source.Bundle) {
		b.PutCmd("systemctl", []string{"is-active", "walinuxagent"}, "active\n", 0)
	})
	installed, running := waagentState()
	if !installed || !running {
		t.Errorf("waagentState() = (%v,%v), want (true,true)", installed, running)
	}
}

func TestWaagentState_InstalledFileFallbackNotRunning(t *testing.T) {
	withFixtureSource(t, func(b *source.Bundle) {
		// lookPath("waagent") unseeded -> falls back to the hardcoded path check.
		b.PutStat("/var/lib/waagent", source.FileMeta{})
		b.PutCmd("systemctl", []string{"is-active", "walinuxagent"}, "inactive\n", 3)
		b.PutCmd("systemctl", []string{"is-active", "waagent"}, "inactive\n", 3)
	})
	installed, running := waagentState()
	if !installed || running {
		t.Errorf("waagentState() = (%v,%v), want (true,false)", installed, running)
	}
}

func TestWaagentState_NotInstalled(t *testing.T) {
	withFixtureSource(t, func(b *source.Bundle) {})
	installed, running := waagentState()
	if installed || running {
		t.Errorf("waagentState() = (%v,%v), want (false,false)", installed, running)
	}
}

func TestAzureTimeSyncConfigured_UsesPTP(t *testing.T) {
	withFixtureSource(t, func(b *source.Bundle) {
		b.PutFile("/etc/chrony.conf", []byte("refclock PHC /dev/ptp_hyperv poll 3 dpoll -2 offset 0\n"))
	})
	checked, uses := azureTimeSyncConfigured()
	if !checked || !uses {
		t.Errorf("azureTimeSyncConfigured() = (%v,%v), want (true,true)", checked, uses)
	}
}

func TestAzureTimeSyncConfigured_NotPTP(t *testing.T) {
	withFixtureSource(t, func(b *source.Bundle) {
		b.PutFile("/etc/chrony.conf", []byte("pool 2.pool.ntp.org iburst\n"))
	})
	checked, uses := azureTimeSyncConfigured()
	if !checked || uses {
		t.Errorf("azureTimeSyncConfigured() = (%v,%v), want (true,false)", checked, uses)
	}
}

func TestAzureTimeSyncConfigured_NoConfig(t *testing.T) {
	withFixtureSource(t, func(b *source.Bundle) {})
	checked, uses := azureTimeSyncConfigured()
	if checked || uses {
		t.Errorf("azureTimeSyncConfigured() = (%v,%v), want (false,false)", checked, uses)
	}
}

// TestAzureCollector_Collect_FullHappyPath drives the entire Collect() pipeline:
// one bonded+up Accelerated-Networking VF, Hyper-V drivers loaded, waagent
// installed+running, Hyper-V PTP time sync, dynamic memory with a ceiling, an
// at-risk temp disk, IMDS disk caching, and a tuned NVMe I/O timeout.
func TestAzureCollector_Collect_FullHappyPath(t *testing.T) {
	withReadlinkFixture(t, map[string]string{
		"/sys/class/net/eth0/device/driver": "/sys/bus/vmbus/drivers/hv_netvsc",
		"/sys/class/net/eth1/device/driver": "/sys/bus/pci/drivers/mlx5_core",
	}, func(b *source.Bundle) {
		b.PutDir("/sys/class/net", []string{"eth0", "eth1"})
		b.PutDir("/sys/class/net/eth0", []string{"lower_eth1"})
		b.PutDir("/sys/class/net/eth1", []string{})
		b.PutFile("/sys/class/net/eth1/operstate", []byte("up\n"))

		b.PutFile("/proc/modules", []byte("hv_netvsc 1 - Live 0x0\nhv_storvsc 1 - Live 0x0\nhv_vmbus 1 - Live 0x0\nhv_balloon 1 - Live 0x0\n"))

		b.PutStat("/usr/sbin/waagent", source.FileMeta{})
		b.PutCmd("systemctl", []string{"is-active", "walinuxagent"}, "active\n", 0)

		b.PutFile("/etc/chrony.conf", []byte("refclock PHC /dev/ptp_hyperv poll 3\n"))

		b.PutCmd("dmesg", []string{}, "hv_balloon: Max. dynamic memory size: 8192 MB\n", 0)

		b.PutFile("/etc/waagent.conf", []byte("ResourceDisk.MountPoint=/mnt/resource\n"))
		b.PutFile("/proc/mounts", []byte("/dev/sdb1 /mnt/resource ext4 rw 0 0\n"))
		b.PutFile("/etc/fstab", []byte("/dev/sdb1 /mnt/resource/pgdata ext4 defaults 0 0\n"))

		b.PutDir("/sys/class/nvme", []string{"nvme0"})
		b.PutFile("/sys/module/nvme_core/parameters/io_timeout", []byte("240\n"))
	})
	// azureDiskCaching's IMDS call is unseeded in this Bundle-only fixture (no Cached
	// override here), so it stays checked=false/nil — asserted below.

	c := NewAzureCollector()
	raw, err := c.Collect(context.Background())
	if err != nil {
		t.Fatalf("Collect() error: %v", err)
	}
	info := raw.(*models.AzureInfo)

	if !info.IsAzure {
		t.Error("IsAzure = false, want true")
	}
	if len(info.SyntheticNICs) != 1 || info.SyntheticNICs[0] != "eth0" {
		t.Errorf("SyntheticNICs = %v, want [eth0]", info.SyntheticNICs)
	}
	if !info.HasVF || len(info.AN) != 1 || info.AN[0].VF != "eth1" || !info.AN[0].Bonded || !info.AN[0].Up {
		t.Errorf("AN = %+v HasVF=%v, unexpected", info.AN, info.HasVF)
	}
	if !info.NetvscLoaded || !info.StorvscLoaded || !info.VMBusLoaded {
		t.Errorf("Netvsc/Storvsc/VMBus loaded = %v/%v/%v, want all true", info.NetvscLoaded, info.StorvscLoaded, info.VMBusLoaded)
	}
	if !info.WAAgentInstalled || !info.WAAgentRunning {
		t.Errorf("WAAgentInstalled=%v WAAgentRunning=%v, want both true", info.WAAgentInstalled, info.WAAgentRunning)
	}
	if !info.TimeSyncChecked || !info.UsesHyperVPTP {
		t.Errorf("TimeSyncChecked=%v UsesHyperVPTP=%v, want both true", info.TimeSyncChecked, info.UsesHyperVPTP)
	}
	if !info.DynamicMemory || info.DynMemMaxMB != 8192 {
		t.Errorf("DynamicMemory=%v DynMemMaxMB=%d, want true/8192", info.DynamicMemory, info.DynMemMaxMB)
	}
	if !info.TempDiskPresent || !info.PersistentDataAtRisk {
		t.Errorf("TempDiskPresent=%v PersistentDataAtRisk=%v, want both true", info.TempDiskPresent, info.PersistentDataAtRisk)
	}
	if info.DisksChecked || info.Disks != nil {
		t.Errorf("DisksChecked=%v Disks=%v, want false/nil (IMDS unseeded in this fixture)", info.DisksChecked, info.Disks)
	}
	if !info.NVMePresent || !info.NVMeIOTimeoutChecked || info.NVMeIOTimeoutSecs != 240 {
		t.Errorf("NVMe fields = present=%v checked=%v secs=%d, want true/true/240", info.NVMePresent, info.NVMeIOTimeoutChecked, info.NVMeIOTimeoutSecs)
	}
}
