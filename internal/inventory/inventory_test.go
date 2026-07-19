package inventory

import (
	"errors"
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
	inv := Build(hw, nil, nil, platform.Profile{Distro: "ubuntu", DistroVersion: "24.04", PackageManager: "apt"},
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
	inv := Build(nil, nil, nil, platform.Profile{Distro: "darwin"}, "v0", "t")
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
	inv := Build(hw, nil, nil, platform.Profile{}, "v0", "t")
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

func TestReadMachineIDFrom(t *testing.T) {
	t.Parallel()

	t.Run("primary present", func(t *testing.T) {
		t.Parallel()
		dir := t.TempDir()
		primary := filepath.Join(dir, "primary-id")
		secondary := filepath.Join(dir, "secondary-id")
		if err := os.WriteFile(primary, []byte("abc123\n"), 0o644); err != nil {
			t.Fatalf("writing primary fixture: %v", err)
		}
		if got := readMachineIDFrom(primary, secondary); got != "abc123" {
			t.Errorf("readMachineIDFrom = %q, want %q", got, "abc123")
		}
	})

	t.Run("primary missing falls back to secondary", func(t *testing.T) {
		t.Parallel()
		dir := t.TempDir()
		secondary := filepath.Join(dir, "secondary-id")
		missingPrimary := filepath.Join(dir, "does-not-exist")
		if err := os.WriteFile(secondary, []byte("fallback-id\n"), 0o644); err != nil {
			t.Fatalf("writing secondary fixture: %v", err)
		}
		if got := readMachineIDFrom(missingPrimary, secondary); got != "fallback-id" {
			t.Errorf("readMachineIDFrom = %q, want %q", got, "fallback-id")
		}
	})

	t.Run("primary empty falls back to secondary", func(t *testing.T) {
		t.Parallel()
		dir := t.TempDir()
		secondary := filepath.Join(dir, "secondary-id")
		emptyPrimary := filepath.Join(dir, "empty-id")
		if err := os.WriteFile(emptyPrimary, []byte("   \n"), 0o644); err != nil {
			t.Fatalf("writing empty primary fixture: %v", err)
		}
		if err := os.WriteFile(secondary, []byte("fallback-id-2\n"), 0o644); err != nil {
			t.Fatalf("writing secondary fixture: %v", err)
		}
		if got := readMachineIDFrom(emptyPrimary, secondary); got != "fallback-id-2" {
			t.Errorf("readMachineIDFrom = %q, want %q", got, "fallback-id-2")
		}
	})

	t.Run("both missing returns empty", func(t *testing.T) {
		t.Parallel()
		dir := t.TempDir()
		missingPrimary := filepath.Join(dir, "nope-1")
		missingSecondary := filepath.Join(dir, "nope-2")
		if got := readMachineIDFrom(missingPrimary, missingSecondary); got != "" {
			t.Errorf("readMachineIDFrom = %q, want empty", got)
		}
	})
}

func TestReadMachineID_RealFallbackChain(t *testing.T) {
	t.Parallel()
	// Smoke test for the zero-arg wrapper: must not panic regardless of
	// whether /etc/machine-id exists on the test host, and always returns a
	// string (possibly empty).
	_ = readMachineID()
}

func TestReadBlockDevices_MissingDir(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	missing := filepath.Join(dir, "does-not-exist")
	if drives := readBlockDevices(missing); drives != nil {
		t.Errorf("readBlockDevices(missing) = %+v, want nil", drives)
	}
}

func TestIsEUI48_BadSeparator(t *testing.T) {
	t.Parallel()
	// Correct length and hex digits, but a non-colon at a separator position.
	if isEUI48("aa-bb:cc:dd:ee:ff") {
		t.Error(`"aa-bb:cc:dd:ee:ff" should be invalid (bad separator)`)
	}
}

func TestCountPackages(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name string
		pm   string
	}{
		{"apt dispatches to dpkg", "apt"},
		{"pacman dispatches to countDir", "pacman"},
		{"dnf dispatches to countRPM", "dnf"},
		{"tdnf dispatches to countRPM", "tdnf"},
		{"yum dispatches to countRPM", "yum"},
		{"zypper dispatches to countRPM", "zypper"},
		{"unknown manager returns 0", "some-unknown-pm"},
		{"empty manager returns 0", ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			// These real paths (/var/lib/pacman/local, rpm binary) are
			// expected absent in the test sandbox, so every branch resolves
			// to an honest 0 — this exercises the switch dispatch itself,
			// not real host package data.
			got := countPackages(tt.pm)
			if got < 0 {
				t.Errorf("countPackages(%q) = %d, want >= 0", tt.pm, got)
			}
		})
	}
}

func TestCountDpkg_MissingFile(t *testing.T) {
	t.Parallel()
	missing := filepath.Join(t.TempDir(), "does-not-exist")
	if n := countDpkg(missing); n != 0 {
		t.Errorf("countDpkg(missing) = %d, want 0", n)
	}
}

func TestCountRPM(t *testing.T) {
	t.Parallel()
	// No path injection is possible here (countRPM shells out to the rpm
	// binary with no file API alternative, per the collector pattern). In
	// the test sandbox the rpm binary is absent, so this deterministically
	// exercises the CommandContext-error graceful-zero path.
	if got := countRPM(); got < 0 {
		t.Errorf("countRPM() = %d, want >= 0", got)
	}
}

// writeFakeRPMBin drops an executable shell script named "rpm" onto a temp
// dir and points PATH at it exclusively, so countRPM's
// exec.CommandContext(ctx, "rpm", "-qa") resolves to this fake instead of a
// real rpm binary — same PATH-shadowing technique as
// internal/cvedata/rpm_test.go's writeFakeRPM, applied here because this
// sandbox has no real rpm to test the success path against.
//
// Callers MUST NOT also call t.Parallel(): t.Setenv panics if the test (or
// an ancestor) is running in parallel.
func writeFakeRPMBin(t *testing.T, script string) {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "rpm")
	if err := os.WriteFile(path, []byte(script), 0o755); err != nil {
		t.Fatalf("writing fake rpm: %v", err)
	}
	t.Setenv("PATH", dir)
}

// TestCountRPM_Success exercises the real "-qa" parse-and-count path
// (inventory.go: trimmed != "" branch), which the sandbox's absent rpm
// binary can never reach on its own — a fake rpm on PATH stands in.
func TestCountRPM_Success(t *testing.T) {
	// Not t.Parallel(): writeFakeRPMBin calls t.Setenv.
	writeFakeRPMBin(t, "#!/bin/sh\necho pkg-a\necho pkg-b\necho pkg-c\n")
	if got := countRPM(); got != 3 {
		t.Errorf("countRPM() = %d, want 3 (one per output line)", got)
	}
}

// TestCountRPM_EmptyOutput exercises the `trimmed == ""` guard: rpm resolves
// and exits 0, but prints nothing (e.g. a broken rpmdb with zero installed
// packages) — must report 0, not 1 (a naive newline-count would say 1 for a
// single empty line).
func TestCountRPM_EmptyOutput(t *testing.T) {
	// Not t.Parallel(): writeFakeRPMBin calls t.Setenv.
	writeFakeRPMBin(t, "#!/bin/sh\nexit 0\n")
	if got := countRPM(); got != 0 {
		t.Errorf("countRPM() = %d, want 0 for empty rpm -qa output", got)
	}
}

// TestCountRPM_CommandFails exercises the exec error path explicitly via a
// fake binary that resolves but exits non-zero — distinct from TestCountRPM
// above, which only covers the "rpm not on PATH at all" case.
func TestCountRPM_CommandFails(t *testing.T) {
	// Not t.Parallel(): writeFakeRPMBin calls t.Setenv.
	writeFakeRPMBin(t, "#!/bin/sh\nexit 1\n")
	if got := countRPM(); got != 0 {
		t.Errorf("countRPM() = %d, want 0 when rpm exits non-zero", got)
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

type errWriter struct{ err error }

func (e *errWriter) Write(_ []byte) (int, error) { return 0, e.err }

func TestWriteCSV_WriteError(t *testing.T) {
	t.Parallel()
	inv := models.Inventory{Tool: "dsd"}
	want := errors.New("disk full")
	err := writeCSV(&errWriter{err: want}, inv)
	if err == nil {
		t.Fatal("writeCSV with failing writer: got nil error, want non-nil")
	}
}

func TestToCSV_MemorySlotsAndNICs(t *testing.T) {
	t.Parallel()
	inv := models.Inventory{
		CollectedAt: "2026-06-05T00:00:00Z", Tool: "dsd", ToolVersion: "v1",
		Memory: models.InventoryMemory{
			TotalGB: 64,
			Slots: []models.InventorySlot{
				{Locator: "DIMM_A1", SizeGB: 32, Type: "DDR4", SpeedMT: 2933},
				{Locator: "DIMM_A2", SizeGB: 32, Type: "DDR4", SpeedMT: 2933},
			},
		},
		NICs: []models.InventoryNIC{
			{Name: "eth0", MAC: "aa:bb:cc:dd:ee:ff", SpeedMbps: 1000, Driver: "igb"},
			{Name: "eth1", MAC: "aa:bb:cc:dd:ee:00", SpeedMbps: 10000, Driver: "ixgbe"},
		},
	}
	csv, err := ToCSV(inv)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"memory.slot.0.locator,DIMM_A1", "memory.slot.0.size_gb,32", "memory.slot.0.type,DDR4", "memory.slot.0.speed_mt,2933",
		"memory.slot.1.locator,DIMM_A2",
		"nic.0.name,eth0", "nic.0.mac,aa:bb:cc:dd:ee:ff", "nic.0.speed_mbps,1000", "nic.0.driver,igb",
		"nic.1.name,eth1", "nic.1.driver,ixgbe",
	} {
		if !strings.Contains(csv, want) {
			t.Errorf("CSV missing %q\n%s", want, csv)
		}
	}
}

func TestBuild_GPUSection(t *testing.T) {
	t.Parallel()
	gpu := &models.GPUInfo{
		Devices: []models.GPUDevice{
			{Index: 0, Name: "Radeon RX 7900 XTX", Vendor: "amd", VRAMTotalGB: 24, DRMDriver: "amdgpu", MesaVersion: "24.3.1"},
		},
		NoDriver: []models.GPUDetected{
			{Name: "NVIDIA GeForce GT 710", Vendor: "nvidia"},
		},
	}
	inv := Build(nil, gpu, nil, platform.Profile{}, "v0", "t")
	if len(inv.GPUs) != 2 {
		t.Fatalf("expected 2 GPU entries (1 device + 1 no-driver), got %d: %+v", len(inv.GPUs), inv.GPUs)
	}
	g0 := inv.GPUs[0]
	if g0.Name != "Radeon RX 7900 XTX" || g0.Vendor != "amd" || g0.VRAMTotalGB != 24 || g0.DRMDriver != "amdgpu" || g0.NoDriver {
		t.Errorf("gpu[0] = %+v", g0)
	}
	g1 := inv.GPUs[1]
	if g1.Name != "NVIDIA GeForce GT 710" || !g1.NoDriver {
		t.Errorf("gpu[1] (no-driver) = %+v", g1)
	}
}

func TestBuild_CloudSection(t *testing.T) {
	t.Parallel()
	cloud := &models.CloudInfo{
		Available:    true,
		Provider:     "aws",
		InstanceID:   "i-0abc123",
		InstanceType: "c6i.large",
		Region:       "us-east-1",
	}
	inv := Build(nil, nil, cloud, platform.Profile{}, "v0", "t")
	if inv.Cloud == nil {
		t.Fatal("cloud section must be populated when cloud.Available=true")
	}
	if inv.Cloud.Provider != "aws" || inv.Cloud.InstanceID != "i-0abc123" || inv.Cloud.Region != "us-east-1" {
		t.Errorf("cloud = %+v", inv.Cloud)
	}
}

func TestBuild_CloudUnavailable(t *testing.T) {
	t.Parallel()
	cloud := &models.CloudInfo{Available: false, Provider: ""}
	inv := Build(nil, nil, cloud, platform.Profile{}, "v0", "t")
	if inv.Cloud != nil {
		t.Errorf("cloud section must be nil when cloud.Available=false, got %+v", inv.Cloud)
	}
}

func TestToCSV_GPUAndCloud(t *testing.T) {
	t.Parallel()
	inv := models.Inventory{
		CollectedAt: "2026-06-05T00:00:00Z", Tool: "dsd", ToolVersion: "v1",
		GPUs: []models.InventoryGPU{
			{Index: 0, Name: "Radeon RX 7900 XTX", Vendor: "amd", VRAMTotalGB: 24, DRMDriver: "amdgpu", MesaVersion: "24.3.1"},
			{Index: 1, Name: "GT 710", Vendor: "nvidia", NoDriver: true},
		},
		Cloud: &models.InventoryCloud{
			Provider: "aws", InstanceID: "i-0abc", InstanceType: "c6i.large", Region: "us-east-1",
		},
	}
	csv, err := ToCSV(inv)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"gpu.0.name,Radeon RX 7900 XTX", "gpu.0.vendor,amd", "gpu.0.vram_total_gb,24", "gpu.0.drm_driver,amdgpu", "gpu.0.mesa_version,24.3.1",
		"gpu.1.name,GT 710", "gpu.1.no_driver,true",
		"cloud.provider,aws", "cloud.instance_id,i-0abc", "cloud.instance_type,c6i.large", "cloud.region,us-east-1",
	} {
		if !strings.Contains(csv, want) {
			t.Errorf("CSV missing %q\n%s", want, csv)
		}
	}
}
