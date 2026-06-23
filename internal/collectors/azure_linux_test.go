//go:build linux

package collectors

import (
	"os"
	"path/filepath"
	"testing"
)

func TestIsAzureGuest(t *testing.T) {
	cases := []struct {
		name                         string
		sysVendor, product, assetTag string
		want                         bool
	}{
		{"azure asset tag", "Microsoft Corporation", "Virtual Machine", azureChassisAssetTag, true},
		{"azure asset tag whitespace", "", "", "  " + azureChassisAssetTag + " ", true},
		{"microsoft azure literal", "Microsoft Azure", "Virtual Machine", "", true},
		{"on-prem hyper-v NOT azure", "Microsoft Corporation", "Virtual Machine", "", false},
		{"vmware not azure", "VMware, Inc.", "VMware7,1", "", false},
		{"empty", "", "", "", false},
	}
	for _, c := range cases {
		if got := isAzureGuest(c.sysVendor, c.product, c.assetTag); got != c.want {
			t.Errorf("%s: isAzureGuest=%v want %v", c.name, got, c.want)
		}
	}
}

func TestAcceleratedVFDriver(t *testing.T) {
	for _, d := range []string{"mlx5_core", "mlx4_en", "mana", "MLX5_CORE"} {
		if !acceleratedVFDriver(d) {
			t.Errorf("%q should be an accelerated VF driver", d)
		}
	}
	for _, d := range []string{"hv_netvsc", "e1000", "virtio_net", ""} {
		if acceleratedVFDriver(d) {
			t.Errorf("%q should NOT be an accelerated VF driver", d)
		}
	}
}

// fakeNIC builds <netDir>/<iface> with a device/driver symlink (base = driver) and an
// operstate file, mimicking the sysfs layout collectNICDrivers/nicOperstateUp read.
func fakeNIC(t *testing.T, netDir, iface, driver, operstate string) {
	t.Helper()
	ifDir := filepath.Join(netDir, iface)
	if err := os.MkdirAll(filepath.Join(ifDir, "device"), 0o755); err != nil {
		t.Fatal(err)
	}
	drvTarget := filepath.Join(netDir, "..", "drivers", driver)
	if err := os.MkdirAll(drvTarget, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(drvTarget, filepath.Join(ifDir, "device", "driver")); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(ifDir, "operstate"), []byte(operstate+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
}

func TestCollectAcceleratedNetworking_BondedVF(t *testing.T) {
	netDir := filepath.Join(t.TempDir(), "net")
	if err := os.MkdirAll(netDir, 0o755); err != nil {
		t.Fatal(err)
	}
	fakeNIC(t, netDir, "eth0", "hv_netvsc", "up")
	fakeNIC(t, netDir, "enP1s2", "mlx5_core", "up")
	// transparent bonding: eth0 has a lower_enP1s2 link
	if err := os.WriteFile(filepath.Join(netDir, "eth0", "lower_enP1s2"), nil, 0o644); err != nil {
		t.Fatal(err)
	}

	syn, ifaces, hasVF := collectAcceleratedNetworking(netDir)
	if len(syn) != 1 || syn[0] != "eth0" {
		t.Fatalf("synthetics = %v, want [eth0]", syn)
	}
	if !hasVF || len(ifaces) != 1 {
		t.Fatalf("ifaces = %+v hasVF=%v, want one VF", ifaces, hasVF)
	}
	vf := ifaces[0]
	if vf.VF != "enP1s2" || vf.Driver != "mlx5_core" || vf.Synthetic != "eth0" || !vf.Bonded || !vf.Up {
		t.Errorf("VF = %+v, want bonded+up enP1s2/mlx5_core under eth0", vf)
	}
}

func TestCollectAcceleratedNetworking_UnbondedVF(t *testing.T) {
	netDir := filepath.Join(t.TempDir(), "net")
	if err := os.MkdirAll(netDir, 0o755); err != nil {
		t.Fatal(err)
	}
	fakeNIC(t, netDir, "eth0", "hv_netvsc", "up")
	fakeNIC(t, netDir, "enP1s2", "mlx5_core", "down") // VF present, NOT linked under eth0

	_, ifaces, hasVF := collectAcceleratedNetworking(netDir)
	if !hasVF || len(ifaces) != 1 {
		t.Fatalf("ifaces = %+v, want one unbonded VF", ifaces)
	}
	if ifaces[0].Bonded || ifaces[0].Up {
		t.Errorf("VF = %+v, want bonded=false up=false", ifaces[0])
	}
}

func TestCollectAcceleratedNetworking_SyntheticOnly(t *testing.T) {
	netDir := filepath.Join(t.TempDir(), "net")
	if err := os.MkdirAll(netDir, 0o755); err != nil {
		t.Fatal(err)
	}
	fakeNIC(t, netDir, "eth0", "hv_netvsc", "up")

	syn, ifaces, hasVF := collectAcceleratedNetworking(netDir)
	if len(syn) != 1 || hasVF || len(ifaces) != 0 {
		t.Errorf("synthetic-only: syn=%v ifaces=%+v hasVF=%v, want [eth0]/none/false", syn, ifaces, hasVF)
	}
}

// ---------- Dynamic Memory ----------

func TestDynamicMemoryState(t *testing.T) {
	const dmesg = "[    1.23] hv_vmbus: registering driver hv_balloon\n[    1.45] hv_balloon: Max. dynamic memory size: 8192 MB\n"

	// hv_balloon loaded + a kernel-logged ceiling → enabled with the max.
	enabled, maxMB := dynamicMemoryState(true, dmesg)
	if !enabled || maxMB != 8192 {
		t.Errorf("dynamicMemoryState(loaded) = (%v, %d), want (true, 8192)", enabled, maxMB)
	}

	// hv_balloon NOT loaded → not enabled, no max (and dmesg is not even consulted).
	if en, mb := dynamicMemoryState(false, dmesg); en || mb != 0 {
		t.Errorf("no hv_balloon: got (%v,%d), want (false,0)", en, mb)
	}

	// Enabled but dmesg unreadable (dmesg_restrict / non-root) → still enabled, max 0.
	if en, mb := dynamicMemoryState(true, ""); !en || mb != 0 {
		t.Errorf("enabled, no dmesg: got (%v,%d), want (true,0)", en, mb)
	}
}

func TestParseHVBalloonMaxMB(t *testing.T) {
	cases := map[string]int{
		"hv_balloon: Max. dynamic memory size: 16384 MB":       16384,
		"prefix\nhv_balloon: Max. dynamic memory size: 512 MB": 512,
		"hv_balloon: Max. dynamic memory size:  0 MB":          0, // clamp non-positive
		"no balloon line here":                                 0,
		"hv_balloon: Max. dynamic memory size: garbled MB":     0,
	}
	for in, want := range cases {
		if got := parseHVBalloonMaxMB(in); got != want {
			t.Errorf("parseHVBalloonMaxMB(%q) = %d, want %d", in, got, want)
		}
	}
}

// ---------- Temp / resource disk ----------

func TestDeviceMountedAt(t *testing.T) {
	const mounts = "/dev/sda1 / ext4 rw 0 0\n/dev/sdb1 /mnt ext4 rw 0 0\ntmpfs /run tmpfs rw 0 0\n"
	if got := deviceMountedAt(mounts, "/mnt"); got != "/dev/sdb1" {
		t.Errorf("deviceMountedAt(/mnt) = %q, want /dev/sdb1", got)
	}
	if got := deviceMountedAt(mounts, "/nonexistent"); got != "" {
		t.Errorf("deviceMountedAt(missing) = %q, want empty", got)
	}
}

func TestFstabHasSubmount(t *testing.T) {
	// A datadir mounted UNDER the temp mount = persistent data on ephemeral storage.
	const risky = "UUID=abc /mnt/resource/data ext4 defaults 0 2\n# comment\n/dev/sdb1 /mnt auto defaults 0 0\n"
	if !fstabHasSubmount(risky, "/mnt") {
		t.Error("fstabHasSubmount should flag /mnt/resource/data under /mnt")
	}
	// The temp mount line itself is NOT a submount.
	const safe = "/dev/sdb1 /mnt/resource auto defaults,nofail 0 0\n"
	if fstabHasSubmount(safe, "/mnt/resource") {
		t.Error("fstabHasSubmount should NOT flag the temp mount line itself")
	}
	if fstabHasSubmount("", "/mnt") {
		t.Error("empty fstab should not flag")
	}
}

func TestTempDiskState(t *testing.T) {
	const waagent = "ResourceDisk.Format=y\nResourceDisk.MountPoint=/mnt/resource\n"
	const mounts = "/dev/sda1 / ext4 rw 0 0\n/dev/sdb1 /mnt/resource ext4 rw 0 0\n"

	present, dev, mount, atRisk := tempDiskState(waagent, mounts, "", false)
	if !present || dev != "/dev/sdb1" || mount != "/mnt/resource" || atRisk {
		t.Errorf("tempDiskState = (%v,%q,%q,%v), want (true,/dev/sdb1,/mnt/resource,false)", present, dev, mount, atRisk)
	}

	// Persistent data layered onto the temp mount → at risk.
	const riskyFstab = "UUID=x /mnt/resource/pgdata ext4 defaults 0 2\n"
	_, _, _, atRisk2 := tempDiskState(waagent, mounts, riskyFstab, false)
	if !atRisk2 {
		t.Error("tempDiskState should flag persistent data under the temp mount")
	}

	// No waagent config, cloud-init image mounts at /mnt.
	const ci = "/dev/sdb1 /mnt ext4 rw 0 0\n"
	p3, _, m3, _ := tempDiskState("", ci, "", false)
	if !p3 || m3 != "/mnt" {
		t.Errorf("cloud-init default: present=%v mount=%q, want true //mnt", p3, m3)
	}

	// Nothing mounted but the /dev/disk/azure/resource marker exists → present.
	p4, dev4, _, _ := tempDiskState("", "/dev/sda1 / ext4 rw 0 0\n", "", true)
	if !p4 || dev4 != "" {
		t.Errorf("marker-only: present=%v dev=%q, want true/empty", p4, dev4)
	}

	// No marker, nothing mounted → absent.
	if p5, _, _, _ := tempDiskState("", "/dev/sda1 / ext4 rw 0 0\n", "", false); p5 {
		t.Error("no marker, no mount → should be absent")
	}
}

// ---------- Managed-disk host caching (IMDS) ----------

func TestParseAzureStorageProfile(t *testing.T) {
	// IMDS returns lun as a string; caching is the host-cache mode.
	const body = `{
		"osDisk": {"name": "myvm_OsDisk_1", "caching": "ReadWrite"},
		"dataDisks": [
			{"name": "data0", "lun": "0", "caching": "None"},
			{"name": "data1", "lun": "1", "caching": "ReadWrite"}
		]
	}`
	checked, disks := parseAzureStorageProfile(body)
	if !checked || len(disks) != 3 {
		t.Fatalf("parseAzureStorageProfile checked=%v disks=%d, want true/3", checked, len(disks))
	}
	if !disks[0].IsOS || disks[0].Caching != "ReadWrite" {
		t.Errorf("OS disk = %+v, want IsOS+ReadWrite", disks[0])
	}
	if disks[1].IsOS || disks[1].Lun != 0 || disks[1].Caching != "None" {
		t.Errorf("data0 = %+v, want data/lun0/None", disks[1])
	}
	if disks[2].Lun != 1 || disks[2].Caching != "ReadWrite" {
		t.Errorf("data1 = %+v, want lun1/ReadWrite", disks[2])
	}

	// Garbled / non-storageProfile body → couldn't-measure, never a silent OK.
	if checked, _ := parseAzureStorageProfile("not json"); checked {
		t.Error("garbled body should be checked=false")
	}
	if checked, _ := parseAzureStorageProfile("{}"); checked {
		t.Error("empty object should be checked=false (couldn't measure)")
	}
}

func TestNVMeDevicesPresent(t *testing.T) {
	// A class dir with at least one controller entry → present.
	dir := filepath.Join(t.TempDir(), "nvme")
	if err := os.MkdirAll(filepath.Join(dir, "nvme0"), 0o755); err != nil {
		t.Fatal(err)
	}
	if !nvmeDevicesPresent(dir) {
		t.Error("a populated /sys/class/nvme should report NVMe present")
	}
	// Empty dir → not present.
	empty := filepath.Join(t.TempDir(), "empty-nvme")
	if err := os.MkdirAll(empty, 0o755); err != nil {
		t.Fatal(err)
	}
	if nvmeDevicesPresent(empty) {
		t.Error("an empty /sys/class/nvme should report NVMe absent")
	}
	// Missing dir → not present (non-NVMe VM).
	if nvmeDevicesPresent(filepath.Join(t.TempDir(), "does-not-exist")) {
		t.Error("a missing /sys/class/nvme should report NVMe absent")
	}
}
