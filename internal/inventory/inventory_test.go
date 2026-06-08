package inventory

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/keyorixhq/dashdiag/internal/models"
	"github.com/keyorixhq/dashdiag/internal/platform"
)

func TestBuild_FromHardwareInfo(t *testing.T) {
	hw := &models.HardwareInfo{
		System: models.HardwareSystem{Vendor: "Dell Inc.", Model: "PowerEdge R740", Board: "0X3D66"},
		CPU:    models.HardwareCPU{Model: "Xeon Gold 6248", Cores: 20, Threads: 40},
		Memory: models.HardwareMemory{TotalGB: 192, Slots: []models.MemorySlot{
			{Locator: "DIMM_A1", SizeGB: 32, Type: "DDR4", SpeedMT: 2933},
		}},
		NICs: []models.HardwareNIC{{Name: "eno1", MAC: "aa:bb:cc:dd:ee:ff", SpeedMbps: 1000, Driver: "igb"}},
	}
	inv := Build(hw, platform.Profile{Distro: "ubuntu", DistroVersion: "24.04", PackageManager: "apt"},
		"v1.2.3", "2026-06-05T00:00:00Z")

	if inv.Tool != "dsd" || inv.ToolVersion != "v1.2.3" {
		t.Errorf("tool meta = %q %q", inv.Tool, inv.ToolVersion)
	}
	if inv.System.Vendor != "Dell Inc." || inv.System.Model != "PowerEdge R740" {
		t.Errorf("system = %+v", inv.System)
	}
	if inv.CPU.Cores != 20 || inv.CPU.Threads != 40 {
		t.Errorf("cpu = %+v", inv.CPU)
	}
	if inv.Memory.TotalGB != 192 || len(inv.Memory.Slots) != 1 {
		t.Errorf("memory = %+v", inv.Memory)
	}
	if len(inv.NICs) != 1 || inv.NICs[0].MAC != "aa:bb:cc:dd:ee:ff" {
		t.Errorf("nics = %+v", inv.NICs)
	}
	if inv.Host.Distro != "ubuntu" || inv.Host.Arch == "" {
		t.Errorf("host = %+v", inv.Host)
	}
	if inv.Software.PackageManager != "apt" {
		t.Errorf("software = %+v", inv.Software)
	}
}

func TestBuild_NilHardware(t *testing.T) {
	// Must not panic when hw is nil (non-Linux path).
	inv := Build(nil, platform.Profile{Distro: "darwin"}, "v0", "t")
	if inv.Host.Arch == "" {
		t.Error("arch should still be populated from runtime")
	}
}

func TestReadBlockDevices(t *testing.T) {
	dir := t.TempDir()
	// Real disk: sda with model/serial/size.
	mk := func(dev string, files map[string]string) {
		base := filepath.Join(dir, dev, "device")
		if err := os.MkdirAll(base, 0o755); err != nil {
			t.Fatal(err)
		}
		for name, content := range files {
			path := filepath.Join(dir, dev, name)
			if strings.HasPrefix(name, "device/") {
				path = filepath.Join(dir, dev, name)
			}
			_ = os.MkdirAll(filepath.Dir(path), 0o755)
			if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
				t.Fatal(err)
			}
		}
	}
	mk("sda", map[string]string{
		"size":          "1953525168", // 512-byte sectors ≈ 1000.2 GB
		"device/model":  "Samsung SSD 870",
		"device/serial": "S5Y2NJ0R123456",
	})
	mk("loop0", map[string]string{"size": "12345"}) // must be skipped

	drives := readBlockDevices(dir)
	if len(drives) != 1 {
		t.Fatalf("expected 1 real drive (loop skipped), got %d: %+v", len(drives), drives)
	}
	d := drives[0]
	if d.Device != "/dev/sda" || d.Model != "Samsung SSD 870" || d.Serial != "S5Y2NJ0R123456" {
		t.Errorf("drive = %+v", d)
	}
	if d.SizeGB < 999 || d.SizeGB > 1001 {
		t.Errorf("size_gb = %v, want ~1000", d.SizeGB)
	}
}

func TestIsVirtualBlock(t *testing.T) {
	for _, name := range []string{"loop0", "ram1", "dm-0", "sr0", "zram0", "md0"} {
		if !isVirtualBlock(name) {
			t.Errorf("%q should be virtual", name)
		}
	}
	for _, name := range []string{"sda", "nvme0n1", "vda", "hda"} {
		if isVirtualBlock(name) {
			t.Errorf("%q should be real", name)
		}
	}
}

func TestIsEUI48(t *testing.T) {
	valid := []string{"aa:bb:cc:dd:ee:ff", "00:1A:2b:3C:4d:5E"}
	for _, m := range valid {
		if !isEUI48(m) {
			t.Errorf("%q should be valid EUI-48", m)
		}
	}
	invalid := []string{"", "00:00:00:00", "00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00", "zz:bb:cc:dd:ee:ff", "aabbccddeeff",
		"00:00:00:00:00:00"} // all-zero MAC (bond/virtual) is not real hardware
	for _, m := range invalid {
		if isEUI48(m) {
			t.Errorf("%q should be invalid", m)
		}
	}
}

func TestBuild_FiltersPseudoNICs(t *testing.T) {
	hw := &models.HardwareInfo{NICs: []models.HardwareNIC{
		{Name: "eth0", MAC: "0a:1a:bc:62:bf:9a"},
		{Name: "sit0", MAC: "00:00:00:00"},
		{Name: "ip6tnl0", MAC: "00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00"},
	}}
	inv := Build(hw, platform.Profile{}, "v0", "t")
	if len(inv.NICs) != 1 || inv.NICs[0].Name != "eth0" {
		t.Errorf("expected only eth0, got %+v", inv.NICs)
	}
}

func TestCountDpkg(t *testing.T) {
	f := filepath.Join(t.TempDir(), "status")
	content := "Package: a\nStatus: install ok installed\n\n" +
		"Package: b\nStatus: deinstall ok config-files\n\n" +
		"Package: c\nStatus: install ok installed\n\n"
	if err := os.WriteFile(f, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	if n := countDpkg(f); n != 2 {
		t.Errorf("countDpkg = %d, want 2", n)
	}
}

func TestToCSV_FlatKeyValue(t *testing.T) {
	inv := models.Inventory{
		CollectedAt: "2026-06-05T00:00:00Z", Tool: "dsd", ToolVersion: "v1",
		Host:   models.InventoryHost{Hostname: "h1", Arch: "amd64"},
		CPU:    models.InventoryCPU{Model: "Xeon", Cores: 4},
		Drives: []models.InventoryDrive{{Device: "/dev/sda", Model: "SSD", SizeGB: 512}},
	}
	csv, err := ToCSV(inv)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"key,value", "host.hostname,h1", "cpu.cores,4", "drive.0.device,/dev/sda", "drive.0.size_gb,512"} {
		if !strings.Contains(csv, want) {
			t.Errorf("CSV missing %q\n%s", want, csv)
		}
	}
	// Empty fields must be omitted (no cpu.threads row when 0).
	if strings.Contains(csv, "cpu.threads") {
		t.Errorf("zero field should be omitted:\n%s", csv)
	}
}
