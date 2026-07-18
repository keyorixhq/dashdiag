//go:build linux

package collectors

import (
	"context"
	"testing"
	"time"

	"github.com/keyorixhq/dashdiag/internal/models"
	"github.com/keyorixhq/dashdiag/internal/source"
)

func TestGPUCollectorIdentity(t *testing.T) {
	t.Parallel()
	c := NewGPUCollector()
	if c.Name() != "GPU" {
		t.Errorf("Name() = %q, want GPU", c.Name())
	}
	if c.Timeout() != 10*time.Second {
		t.Errorf("Timeout() = %v, want 10s", c.Timeout())
	}
	if c.Deep {
		t.Error("NewGPUCollector: expected Deep=false")
	}
	if !NewGPUDeepCollector().Deep {
		t.Error("NewGPUDeepCollector: expected Deep=true")
	}
}

func TestNaAtoi(t *testing.T) {
	t.Parallel()
	tests := []struct {
		in     string
		wantN  int
		wantOK bool
	}{
		{"123", 123, true},
		{" 45 ", 45, true},
		{"", 0, false},
		{"[N/A]", 0, false},
		{"ERR!", 0, false},
		{"abc", 0, false},
	}
	for _, tt := range tests {
		n, ok := naAtoi(tt.in)
		if n != tt.wantN || ok != tt.wantOK {
			t.Errorf("naAtoi(%q) = (%d, %v), want (%d, %v)", tt.in, n, ok, tt.wantN, tt.wantOK)
		}
	}
}

func TestParseNvidiaSMILine_Happy(t *testing.T) {
	t.Parallel()
	line := "0, RTX 4090, 65, 42, 8192, 24576, 430, 550.54.14, 450"
	dev, driverVer, err := parseNvidiaSMILine(line)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if driverVer != "550.54.14" {
		t.Errorf("driverVer = %q, want 550.54.14", driverVer)
	}
	if dev.Index != 0 || dev.Name != "RTX 4090" || dev.TempC != 65 || dev.UtilPct != 42 {
		t.Errorf("dev = %+v, unexpected fields", dev)
	}
	if dev.MemUsedMB != 8192 || dev.MemTotalMB != 24576 {
		t.Errorf("mem fields = %d/%d", dev.MemUsedMB, dev.MemTotalMB)
	}
	if dev.Unreadable {
		t.Error("expected Unreadable=false")
	}
	// power=430 >= 0.95*450=427.5 -> throttling
	if !dev.Throttling {
		t.Error("expected Throttling=true at 430W/450W limit")
	}
}

func TestParseNvidiaSMILine_Unreadable(t *testing.T) {
	t.Parallel()
	line := "0, RTX 4090, [N/A], 0, 0, [N/A], [N/A], 550.54.14"
	dev, _, err := parseNvidiaSMILine(line)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !dev.Unreadable {
		t.Error("expected Unreadable=true when both temp and memTotal are N/A")
	}
}

func TestParseNvidiaSMILine_PartialNA_NotUnreadable(t *testing.T) {
	t.Parallel()
	// temp N/A but memTotal present -- a legit MIG/vGPU instance, not a dead card.
	line := "0, RTX 4090, [N/A], 42, 100, 24576, 50, 550.54.14"
	dev, _, err := parseNvidiaSMILine(line)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if dev.Unreadable {
		t.Error("expected Unreadable=false when only one metric is N/A")
	}
}

func TestParseNvidiaSMILine_TooFewFields(t *testing.T) {
	t.Parallel()
	_, _, err := parseNvidiaSMILine("0, RTX 4090, 65")
	if err == nil {
		t.Fatal("expected error for too few fields")
	}
}

func TestParseNvidiaSMILine_NoPowerLimitField(t *testing.T) {
	t.Parallel()
	// Only 8 fields -- older nvidia-smi without power.limit.
	line := "0, RTX 4090, 65, 42, 8192, 24576, 350, 550.54.14"
	dev, _, err := parseNvidiaSMILine(line)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if dev.TDPLimitW != 0 {
		t.Errorf("TDPLimitW = %v, want 0", dev.TDPLimitW)
	}
	if dev.Throttling {
		t.Error("expected Throttling=false with no power limit")
	}
}

func TestParseGPUProcesses(t *testing.T) {
	t.Parallel()
	out := "1234, 6823 MiB, python3\n5678, 100, blender\n9999, [N/A], compositor\n\n"
	procs := parseGPUProcesses(out)
	if len(procs) != 3 {
		t.Fatalf("got %d procs, want 3", len(procs))
	}
	if procs[0].PID != 1234 || procs[0].MemUseMB != 6823 || procs[0].Name != "python3" {
		t.Errorf("procs[0] = %+v", procs[0])
	}
	if procs[1].MemUseMB != 100 {
		t.Errorf("procs[1].MemUseMB = %d, want 100", procs[1].MemUseMB)
	}
	if procs[2].MemUseMB != 0 {
		t.Errorf("procs[2].MemUseMB = %d, want 0 for N/A", procs[2].MemUseMB)
	}
}

func TestParseGPUProcesses_Empty(t *testing.T) {
	t.Parallel()
	if procs := parseGPUProcesses("  \n"); procs != nil {
		t.Errorf("expected nil, got %v", procs)
	}
}

func TestCollectGPUProcesses(t *testing.T) {
	withFixtureSource(t, func(b *source.Bundle) {
		b.PutCmd("nvidia-smi", []string{
			"--query-compute-apps=pid,used_memory,name", "--format=csv,noheader,nounits",
		}, "1234, 6823 MiB, python3\n", 0)
	})
	procs := collectGPUProcesses(context.Background())
	if len(procs) != 1 || procs[0].Name != "python3" {
		t.Errorf("procs = %+v", procs)
	}
}

func TestCollectGPUProcesses_CmdFails(t *testing.T) {
	withFixtureSource(t, func(b *source.Bundle) {
		b.PutCmdNotFound("nvidia-smi", []string{
			"--query-compute-apps=pid,used_memory,name", "--format=csv,noheader,nounits",
		})
	})
	if procs := collectGPUProcesses(context.Background()); procs != nil {
		t.Errorf("expected nil on cmd failure, got %v", procs)
	}
}

func TestHasNvidiaCard_True(t *testing.T) {
	withFixtureSource(t, func(b *source.Bundle) {
		b.PutGlob("/sys/class/drm/card[0-9]", []string{"/sys/class/drm/card0"})
		b.PutFile("/sys/class/drm/card0/device/vendor", []byte("0x10de\n"))
	})
	if !hasNvidiaCard() {
		t.Error("expected true")
	}
}

func TestHasNvidiaCard_False(t *testing.T) {
	withFixtureSource(t, func(b *source.Bundle) {
		b.PutGlob("/sys/class/drm/card[0-9]", []string{"/sys/class/drm/card0"})
		b.PutFile("/sys/class/drm/card0/device/vendor", []byte("0x1002\n"))
	})
	if hasNvidiaCard() {
		t.Error("expected false")
	}
}

func TestAmdCardPaths(t *testing.T) {
	withFixtureSource(t, func(b *source.Bundle) {
		b.PutGlob("/sys/class/drm/card[0-9]", []string{
			"/sys/class/drm/card0", "/sys/class/drm/card1",
		})
		b.PutFile("/sys/class/drm/card0/device/vendor", []byte("0x1002\n"))
		b.PutFile("/sys/class/drm/card1/device/vendor", []byte("0x10de\n"))
	})
	cards := amdCardPaths()
	if len(cards) != 1 || cards[0] != "/sys/class/drm/card0" {
		t.Errorf("cards = %v, want [/sys/class/drm/card0]", cards)
	}
}

// TestAmdCardPaths_GlobError guards the err != nil branch: an unseeded glob
// pattern (Replay's ErrNotRecorded) must return nil, not panic.
func TestAmdCardPaths_GlobError(t *testing.T) {
	withFixtureSource(t, func(b *source.Bundle) {
		// /sys/class/drm/card[0-9] intentionally left unseeded.
	})
	if cards := amdCardPaths(); cards != nil {
		t.Errorf("cards = %v, want nil on a glob error", cards)
	}
}

func TestCollectAMDGPUs(t *testing.T) {
	withReadlinkFixture(t, map[string]string{
		"/sys/class/drm/card0/device/driver": "../../../bus/pci/drivers/amdgpu",
	}, func(b *source.Bundle) {
		devPath := "/sys/class/drm/card0/device"
		b.PutGlob(devPath+"/hwmon/hwmon*/temp1_input", []string{devPath + "/hwmon/hwmon0/temp1_input"})
		b.PutFile(devPath+"/hwmon/hwmon0/temp1_input", []byte("65000\n"))
		b.PutGlob(devPath+"/hwmon/hwmon*/temp2_input", []string{devPath + "/hwmon/hwmon0/temp2_input"})
		b.PutFile(devPath+"/hwmon/hwmon0/temp2_input", []byte("75000\n"))
		b.PutGlob(devPath+"/hwmon/hwmon*/temp3_input", []string{devPath + "/hwmon/hwmon0/temp3_input"})
		b.PutFile(devPath+"/hwmon/hwmon0/temp3_input", []byte("60000\n"))
		b.PutFile(devPath+"/gpu_busy_percent", []byte("33\n"))
		b.PutFile(devPath+"/pp_dpm_sclk", []byte("0: 200Mhz\n1: 1000Mhz *\n2: 1600Mhz\n"))
		b.PutFile(devPath+"/mem_info_vram_used", []byte("1073741824\n"))   // 1 GiB
		b.PutFile(devPath+"/mem_info_vram_total", []byte("17179869184\n")) // 16 GiB
		b.PutFile(devPath+"/mem_info_gtt_total", []byte(""))
		b.PutGlob(devPath+"/hwmon/hwmon*/power1_cap", []string{devPath + "/hwmon/hwmon0/power1_cap"})
		b.PutFile(devPath+"/hwmon/hwmon0/power1_cap", []byte("300000000\n"))
		b.PutGlob(devPath+"/hwmon/hwmon*/power1_cap_max", []string{devPath + "/hwmon/hwmon0/power1_cap_max"})
		b.PutFile(devPath+"/hwmon/hwmon0/power1_cap_max", []byte("350000000\n"))
		b.PutGlob(devPath+"/hwmon/hwmon*/power1_input", []string{devPath + "/hwmon/hwmon0/power1_input"})
		b.PutFile(devPath+"/hwmon/hwmon0/power1_input", []byte("290000000\n"))
		b.PutGlob(devPath+"/hwmon/hwmon*/name", []string{devPath + "/hwmon/hwmon0/name"})
		b.PutFile(devPath+"/hwmon/hwmon0/name", []byte("amdgpu\n"))
		b.PutFile(devPath+"/uevent", []byte("PCI_ID=1002:73BF\n"))
		b.PutFile(devPath+"/power_dpm_force_performance_level", []byte("manual\n"))
	})

	devices := collectAMDGPUs([]string{"/sys/class/drm/card0"}, true)
	if len(devices) != 1 {
		t.Fatalf("got %d devices, want 1", len(devices))
	}
	dev := devices[0]
	if dev.Vendor != "amd" || dev.DRMDriver != "amdgpu" {
		t.Errorf("Vendor/DRMDriver = %q/%q", dev.Vendor, dev.DRMDriver)
	}
	if dev.Name != "AMD GPU (73BF)" {
		t.Errorf("Name = %q", dev.Name)
	}
	if dev.TempC != 65 || dev.TempJunctionC != 75 || dev.TempMemC != 60 {
		t.Errorf("temps = %d/%d/%d", dev.TempC, dev.TempJunctionC, dev.TempMemC)
	}
	if dev.UtilPct != 33 {
		t.Errorf("UtilPct = %d, want 33", dev.UtilPct)
	}
	if dev.ClockMHz != 1000 || dev.ClockMaxMHz != 1600 {
		t.Errorf("clocks = %d/%d", dev.ClockMHz, dev.ClockMaxMHz)
	}
	if dev.MemUsedMB != 1024 || dev.MemTotalMB != 16384 {
		t.Errorf("mem = %d/%d MB", dev.MemUsedMB, dev.MemTotalMB)
	}
	if dev.IsAPU {
		t.Error("expected IsAPU=false: 16GB VRAM and no GTT pool")
	}
	if dev.TDPLimitW != 300 || dev.TDPMaxW != 350 || dev.TDPCurrentW != 290 {
		t.Errorf("TDP = %v/%v/%v", dev.TDPLimitW, dev.TDPMaxW, dev.TDPCurrentW)
	}
	if dev.PowerDrawW != 290 {
		t.Errorf("PowerDrawW = %v, want 290 (from TDPCurrentW)", dev.PowerDrawW)
	}
	if !dev.Throttling {
		t.Error("expected Throttling=true: 290/300 >= 0.95")
	}
	if dev.PowerDPMLevel != "manual" {
		t.Errorf("PowerDPMLevel = %q, want manual (deep=true)", dev.PowerDPMLevel)
	}
}

func TestCollectAMDGPUs_APU_PowerAverageFallback_NotDeep(t *testing.T) {
	withReadlinkFixture(t, map[string]string{
		"/sys/class/drm/card0/device/driver": "../../../bus/pci/drivers/amdgpu",
	}, func(b *source.Bundle) {
		devPath := "/sys/class/drm/card0/device"
		b.PutFile(devPath+"/mem_info_vram_used", []byte("536870912\n"))   // 0.5 GiB
		b.PutFile(devPath+"/mem_info_vram_total", []byte("1073741824\n")) // 1 GiB -- APU carveout
		b.PutFile(devPath+"/mem_info_gtt_total", []byte("8589934592\n"))  // shared pool present
		b.PutGlob(devPath+"/hwmon/hwmon*/power1_input", []string{})
		b.PutGlob(devPath+"/hwmon/hwmon*/power1_average", []string{devPath + "/hwmon/hwmon0/power1_average"})
		b.PutFile(devPath+"/hwmon/hwmon0/power1_average", []byte("15000000\n"))
		b.PutFile(devPath+"/uevent", []byte(""))
	})

	devices := collectAMDGPUs([]string{"/sys/class/drm/card0"}, false)
	dev := devices[0]
	if !dev.IsAPU {
		t.Error("expected IsAPU=true: <2GB VRAM plus GTT pool present")
	}
	if dev.TDPCurrentW != 0 {
		t.Errorf("TDPCurrentW = %v, want 0 (no power1_input)", dev.TDPCurrentW)
	}
	if dev.PowerDrawW != 15 {
		t.Errorf("PowerDrawW = %v, want 15 (fallback to power1_average)", dev.PowerDrawW)
	}
	if dev.PowerDPMLevel != "" {
		t.Errorf("PowerDPMLevel = %q, want empty (deep=false)", dev.PowerDPMLevel)
	}
	if dev.Name != "AMD GPU" {
		t.Errorf("Name = %q, want fallback AMD GPU", dev.Name)
	}
}

func TestCollectIntelGPUs(t *testing.T) {
	withReadlinkFixture(t, map[string]string{
		"/sys/class/drm/card0/device/driver": "../../../bus/pci/drivers/i915",
	}, func(b *source.Bundle) {
		b.PutGlob("/sys/class/drm/card[0-9]", []string{"/sys/class/drm/card0"})
		devPath := "/sys/class/drm/card0/device"
		b.PutFile(devPath+"/vendor", []byte("0x8086\n"))
		b.PutFile(devPath+"/uevent", []byte("PCI_ID=8086:9BC4\n"))
		b.PutGlob(devPath+"/hwmon/hwmon*/temp1_input", []string{devPath + "/hwmon/hwmon0/temp1_input"})
		b.PutFile(devPath+"/hwmon/hwmon0/temp1_input", []byte("50000\n"))
		b.PutGlob(devPath+"/hwmon/hwmon*/power1_input", []string{devPath + "/hwmon/hwmon0/power1_input"})
		b.PutFile(devPath+"/hwmon/hwmon0/power1_input", []byte("5000000\n"))
	})
	devices := collectIntelGPUs()
	if len(devices) != 1 {
		t.Fatalf("got %d devices, want 1", len(devices))
	}
	dev := devices[0]
	if dev.Vendor != "intel" || dev.DRMDriver != "i915" {
		t.Errorf("Vendor/DRMDriver = %q/%q", dev.Vendor, dev.DRMDriver)
	}
	if dev.Name != "Intel GPU (9BC4)" {
		t.Errorf("Name = %q", dev.Name)
	}
	if dev.TempC != 50 || dev.PowerDrawW != 5 {
		t.Errorf("TempC/PowerDrawW = %d/%v", dev.TempC, dev.PowerDrawW)
	}
}

func TestCollectIntelGPUs_NoMatchingVendor(t *testing.T) {
	withFixtureSource(t, func(b *source.Bundle) {
		b.PutGlob("/sys/class/drm/card[0-9]", []string{"/sys/class/drm/card0"})
		b.PutFile("/sys/class/drm/card0/device/vendor", []byte("0x1002\n"))
	})
	if devices := collectIntelGPUs(); devices != nil {
		t.Errorf("expected nil, got %v", devices)
	}
}

func TestParseDPMSclk_NegativeIgnored(t *testing.T) {
	t.Parallel()
	// Garbled sysfs producing a negative clock must not be treated as current/max.
	cur, max := parseDPMSclk("0: -5Mhz *\n1: 800Mhz\n")
	if cur != 0 {
		t.Errorf("cur = %d, want 0 (negative ignored)", cur)
	}
	if max != 800 {
		t.Errorf("max = %d, want 800", max)
	}
}

func TestDetectMesaVersion_NoDisplay(t *testing.T) {
	t.Setenv("DISPLAY", "")
	t.Setenv("WAYLAND_DISPLAY", "")
	if v := detectMesaVersion(context.Background()); v != "" {
		t.Errorf("got %q, want empty with no display", v)
	}
}

func TestDetectMesaVersion_Happy(t *testing.T) {
	t.Setenv("DISPLAY", ":0")
	withFixtureSource(t, func(b *source.Bundle) {
		b.PutCmd("glxinfo", []string{"-B"},
			"name of display: :0\nOpenGL version string: 4.6 (Compatibility Profile) Mesa 24.3.1\n", 0)
	})
	if v := detectMesaVersion(context.Background()); v != "24.3.1" {
		t.Errorf("got %q, want 24.3.1", v)
	}
}

func TestDetectMesaVersion_CmdFails(t *testing.T) {
	t.Setenv("DISPLAY", ":0")
	withFixtureSource(t, func(b *source.Bundle) {
		b.PutCmdNotFound("glxinfo", []string{"-B"})
	})
	if v := detectMesaVersion(context.Background()); v != "" {
		t.Errorf("got %q, want empty on cmd failure", v)
	}
}

func TestDetectMesaVersion_NoMesaInOutput(t *testing.T) {
	t.Setenv("DISPLAY", ":0")
	withFixtureSource(t, func(b *source.Bundle) {
		b.PutCmd("glxinfo", []string{"-B"}, "OpenGL version string: 4.6 NVIDIA 550.54.14\n", 0)
	})
	if v := detectMesaVersion(context.Background()); v != "" {
		t.Errorf("got %q, want empty when no Mesa marker present", v)
	}
}

func TestDrmDriver(t *testing.T) {
	withReadlinkFixture(t, map[string]string{
		"/sys/class/drm/card0/device/driver": "../../../bus/pci/drivers/amdgpu",
	}, func(b *source.Bundle) {})
	if d := drmDriver("/sys/class/drm/card0/device"); d != "amdgpu" {
		t.Errorf("got %q, want amdgpu", d)
	}
}

func TestDrmDriver_NoLink(t *testing.T) {
	withFixtureSource(t, func(b *source.Bundle) {})
	if d := drmDriver("/sys/class/drm/card0/device"); d != "" {
		t.Errorf("got %q, want empty", d)
	}
}

func TestCardIndex_MultiDigit(t *testing.T) {
	t.Parallel()
	if n := cardIndex("/sys/class/drm/card13"); n != 13 {
		t.Errorf("got %d, want 13", n)
	}
}

func TestIntelGPUName(t *testing.T) {
	withFixtureSource(t, func(b *source.Bundle) {
		b.PutFile("/sys/class/drm/card0/device/uevent", []byte("PCI_ID=8086:9BC4\n"))
	})
	if n := intelGPUName("/sys/class/drm/card0/device"); n != "Intel GPU (9BC4)" {
		t.Errorf("got %q", n)
	}
}

func TestIntelGPUName_NoPCIID(t *testing.T) {
	withFixtureSource(t, func(b *source.Bundle) {
		b.PutFile("/sys/class/drm/card0/device/uevent", []byte("DRIVER=i915\n"))
	})
	if n := intelGPUName("/sys/class/drm/card0/device"); n != "Intel GPU" {
		t.Errorf("got %q, want fallback", n)
	}
}

func TestReadSysfsInt64(t *testing.T) {
	withFixtureSource(t, func(b *source.Bundle) {
		b.PutFile("/x", []byte("123456789012\n"))
	})
	if n := readSysfsInt64("/x"); n != 123456789012 {
		t.Errorf("got %d", n)
	}
}

func TestReadSysfsInt64_Garbage(t *testing.T) {
	withFixtureSource(t, func(b *source.Bundle) {
		b.PutFile("/x", []byte("not-a-number\n"))
	})
	if n := readSysfsInt64("/x"); n != 0 {
		t.Errorf("got %d, want 0", n)
	}
}

func TestReadSysfsMilliC(t *testing.T) {
	withFixtureSource(t, func(b *source.Bundle) {
		b.PutGlob("/x*", []string{"/x0"})
		b.PutFile("/x0", []byte("65500\n"))
	})
	if c := readSysfsMilliC("/x*"); c != 65 {
		t.Errorf("got %d, want 65", c)
	}
}

func TestReadSysfsMilliC_AbsentGlob(t *testing.T) {
	withFixtureSource(t, func(b *source.Bundle) {
		b.PutGlob("/x*", nil)
	})
	if c := readSysfsMilliC("/x*"); c != 0 {
		t.Errorf("got %d, want 0", c)
	}
}

func TestReadSysfsMilliC_Garbage(t *testing.T) {
	withFixtureSource(t, func(b *source.Bundle) {
		b.PutGlob("/x*", []string{"/x0"})
		b.PutFile("/x0", []byte("garbage\n"))
	})
	if c := readSysfsMilliC("/x*"); c != 0 {
		t.Errorf("got %d, want 0", c)
	}
}

func TestReadSysfsMicroW(t *testing.T) {
	withFixtureSource(t, func(b *source.Bundle) {
		b.PutGlob("/x*", []string{"/x0"})
		b.PutFile("/x0", []byte("15000000\n"))
	})
	if w := readSysfsMicroW("/x*"); w != 15 {
		t.Errorf("got %v, want 15", w)
	}
}

func TestReadSysfsMicroW_Absent(t *testing.T) {
	withFixtureSource(t, func(b *source.Bundle) {
		b.PutGlob("/x*", nil)
	})
	if w := readSysfsMicroW("/x*"); w != 0 {
		t.Errorf("got %v, want 0", w)
	}
}

// TestReadSysfsMicroW_Garbage guards the ParseInt-error branch — a matched
// file exists but its content isn't a valid integer.
func TestReadSysfsMicroW_Garbage(t *testing.T) {
	withFixtureSource(t, func(b *source.Bundle) {
		b.PutGlob("/x*", []string{"/x0"})
		b.PutFile("/x0", []byte("not-a-number\n"))
	})
	if w := readSysfsMicroW("/x*"); w != 0 {
		t.Errorf("got %v, want 0", w)
	}
}

func TestDetectNvidiaWithoutSMI_Nouveau(t *testing.T) {
	withFixtureSource(t, func(b *source.Bundle) {
		b.PutGlob("/sys/class/drm/card[0-9]", []string{"/sys/class/drm/card0"})
		devPath := "/sys/class/drm/card0/device"
		b.PutFile(devPath+"/vendor", []byte("0x10de\n"))
		b.PutFile(devPath+"/uevent", []byte("DRIVER=nouveau\nPCI_ID=10de:2684\nPCI_SLOT_NAME=0000:01:00.0\n"))
	})
	found := detectNvidiaWithoutSMI()
	if len(found) != 1 {
		t.Fatalf("got %d, want 1", len(found))
	}
	if found[0].Name != "NVIDIA GPU (2684) [nouveau]" {
		t.Errorf("Name = %q", found[0].Name)
	}
	if found[0].PCIAddr != "0000:01:00.0" {
		t.Errorf("PCIAddr = %q", found[0].PCIAddr)
	}
}

func TestDetectNvidiaWithoutSMI_NoDriverBound(t *testing.T) {
	withFixtureSource(t, func(b *source.Bundle) {
		b.PutGlob("/sys/class/drm/card[0-9]", []string{"/sys/class/drm/card0"})
		devPath := "/sys/class/drm/card0/device"
		b.PutFile(devPath+"/vendor", []byte("0x10de\n"))
		b.PutFile(devPath+"/uevent", []byte(""))
	})
	found := detectNvidiaWithoutSMI()
	if len(found) != 1 || found[0].Name != "NVIDIA GPU" {
		t.Errorf("got %+v", found)
	}
}

func TestDetectNvidiaWithoutSMI_ProprietaryBoundSkipped(t *testing.T) {
	withFixtureSource(t, func(b *source.Bundle) {
		b.PutGlob("/sys/class/drm/card[0-9]", []string{"/sys/class/drm/card0"})
		devPath := "/sys/class/drm/card0/device"
		b.PutFile(devPath+"/vendor", []byte("0x10de\n"))
		b.PutFile(devPath+"/uevent", []byte("DRIVER=nvidia\n"))
	})
	if found := detectNvidiaWithoutSMI(); found != nil {
		t.Errorf("expected nil, got %v", found)
	}
}

func TestDetectNvidiaWithoutSMI_NonNvidiaSkipped(t *testing.T) {
	withFixtureSource(t, func(b *source.Bundle) {
		b.PutGlob("/sys/class/drm/card[0-9]", []string{"/sys/class/drm/card0"})
		b.PutFile("/sys/class/drm/card0/device/vendor", []byte("0x1002\n"))
	})
	if found := detectNvidiaWithoutSMI(); found != nil {
		t.Errorf("expected nil, got %v", found)
	}
}

func TestAmdGPUName_FromHwmon(t *testing.T) {
	withFixtureSource(t, func(b *source.Bundle) {
		b.PutGlob("/x/hwmon/hwmon*/name", []string{"/x/hwmon/hwmon0/name"})
		b.PutFile("/x/hwmon/hwmon0/name", []byte("R9NANO\n"))
	})
	if n := amdGPUName("/x"); n != "R9NANO" {
		t.Errorf("got %q", n)
	}
}

func TestAmdGPUName_FallbackPCIID(t *testing.T) {
	withFixtureSource(t, func(b *source.Bundle) {
		b.PutGlob("/x/hwmon/hwmon*/name", []string{"/x/hwmon/hwmon0/name"})
		b.PutFile("/x/hwmon/hwmon0/name", []byte("amdgpu\n"))
		b.PutFile("/x/uevent", []byte("PCI_ID=1002:687F\n"))
	})
	if n := amdGPUName("/x"); n != "AMD GPU (687F)" {
		t.Errorf("got %q", n)
	}
}

func TestAmdGPUName_FullFallback(t *testing.T) {
	withFixtureSource(t, func(b *source.Bundle) {
		b.PutGlob("/x/hwmon/hwmon*/name", nil)
		b.PutFile("/x/uevent", []byte(""))
	})
	if n := amdGPUName("/x"); n != "AMD GPU" {
		t.Errorf("got %q", n)
	}
}

func TestReadSysfsStr(t *testing.T) {
	withFixtureSource(t, func(b *source.Bundle) {
		b.PutFile("/x", []byte("hello\n"))
	})
	if s := readSysfsStr("/x"); s != "hello\n" {
		t.Errorf("got %q", s)
	}
}

func TestReadSysfsStr_Missing(t *testing.T) {
	withFixtureSource(t, func(b *source.Bundle) {})
	if s := readSysfsStr("/nope"); s != "" {
		t.Errorf("got %q, want empty", s)
	}
}

func TestReadSysfsFirstGlob(t *testing.T) {
	withFixtureSource(t, func(b *source.Bundle) {
		b.PutGlob("/x*", []string{"/x0", "/x1"})
		b.PutFile("/x0", []byte("first\n"))
	})
	if s := readSysfsFirstGlob("/x*"); s != "first\n" {
		t.Errorf("got %q", s)
	}
}

func TestReadSysfsFirstGlob_NoMatches(t *testing.T) {
	withFixtureSource(t, func(b *source.Bundle) {
		b.PutGlob("/x*", nil)
	})
	if s := readSysfsFirstGlob("/x*"); s != "" {
		t.Errorf("got %q, want empty", s)
	}
}

// TestGPUCollector_Collect_NoGPUs exercises the fully-empty gate: no DRM cards,
// no nvidia-smi, no display -- everything degrades to an empty, zero-value info.
func TestGPUCollector_Collect_NoGPUs(t *testing.T) {
	t.Setenv("DISPLAY", "")
	t.Setenv("WAYLAND_DISPLAY", "")
	withFixtureSource(t, func(b *source.Bundle) {
		b.PutGlob("/sys/class/drm/card[0-9]", nil)
		b.PutCmdNotFound("nvidia-smi",
			[]string{
				"--query-gpu=index,name,temperature.gpu,utilization.gpu,memory.used,memory.total,power.draw,driver_version,power.limit",
				"--format=csv,noheader,nounits",
			})
	})
	got, err := NewGPUCollector().Collect(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	info := got.(*models.GPUInfo)
	if len(info.Devices) != 0 || len(info.NoDriver) != 0 || info.Status != "" {
		t.Errorf("info = %+v, want fully empty", info)
	}
}

// TestGPUCollector_Collect_NvidiaHappyPath drives the full nvidia-smi success
// path, including the util>=50 branch that triggers a compute-apps query.
func TestGPUCollector_Collect_NvidiaHappyPath(t *testing.T) {
	t.Setenv("DISPLAY", "")
	t.Setenv("WAYLAND_DISPLAY", "")
	withFixtureSource(t, func(b *source.Bundle) {
		b.PutGlob("/sys/class/drm/card[0-9]", nil)
		b.PutCmd("nvidia-smi",
			[]string{
				"--query-gpu=index,name,temperature.gpu,utilization.gpu,memory.used,memory.total,power.draw,driver_version,power.limit",
				"--format=csv,noheader,nounits",
			},
			"0, RTX 4090, 72, 80, 8192, 24576, 350, 550.54.14, 450\n", 0)
		b.PutCmd("nvidia-smi",
			[]string{"--query-compute-apps=pid,used_memory,name", "--format=csv,noheader,nounits"},
			"4242, 8000 MiB, blender\n", 0)
	})
	got, err := NewGPUCollector().Collect(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	info := got.(*models.GPUInfo)
	if len(info.Devices) != 1 {
		t.Fatalf("got %d devices, want 1", len(info.Devices))
	}
	dev := info.Devices[0]
	if dev.Vendor != "nvidia" || dev.DRMDriver != "nvidia" {
		t.Errorf("Vendor/DRMDriver = %q/%q", dev.Vendor, dev.DRMDriver)
	}
	if info.DriverVersion != "550.54.14" {
		t.Errorf("DriverVersion = %q", info.DriverVersion)
	}
	if len(dev.Processes) != 1 || dev.Processes[0].Name != "blender" {
		t.Errorf("Processes = %+v, want the util>=50 branch to have queried compute-apps", dev.Processes)
	}
}

// TestGPUCollector_Collect_NvidiaMultiLineSkipsGarbled guards the per-line
// loop's continue branches: a blank line and an unparseable line must be
// skipped without aborting the well-formed lines around them.
func TestGPUCollector_Collect_NvidiaMultiLineSkipsGarbled(t *testing.T) {
	t.Setenv("DISPLAY", "")
	t.Setenv("WAYLAND_DISPLAY", "")
	withFixtureSource(t, func(b *source.Bundle) {
		b.PutGlob("/sys/class/drm/card[0-9]", nil)
		b.PutCmd("nvidia-smi",
			[]string{
				"--query-gpu=index,name,temperature.gpu,utilization.gpu,memory.used,memory.total,power.draw,driver_version,power.limit",
				"--format=csv,noheader,nounits",
			},
			"0, RTX 4090, 60, 20, 8192, 24576, 350, 550.54.14, 450\n"+
				"\n"+ // blank line -> skipped
				"garbled, not, enough, fields\n"+ // unparseable -> continue
				"1, RTX 3080, 65, 30, 4096, 10240, 300, 550.54.14, 400\n",
			0)
	})
	got, err := NewGPUCollector().Collect(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	info := got.(*models.GPUInfo)
	if len(info.Devices) != 2 {
		t.Fatalf("got %d devices, want 2 (garbled/blank lines skipped)", len(info.Devices))
	}
}

// TestGPUCollector_Collect_MesaAppliedToAMD guards the mesa-version
// application branch onto AMD devices — every other AMD Collect test forces
// DISPLAY/WAYLAND_DISPLAY empty, which short-circuits detectMesaVersion
// before that branch is ever reached.
func TestGPUCollector_Collect_MesaAppliedToAMD(t *testing.T) {
	t.Setenv("DISPLAY", ":0")
	t.Setenv("WAYLAND_DISPLAY", "")
	links := map[string]string{
		"/sys/class/drm/card0/device/driver": "../../../bus/pci/drivers/amdgpu",
	}
	b := source.NewBundle()
	devPath := "/sys/class/drm/card0/device"
	b.PutGlob("/sys/class/drm/card[0-9]", []string{"/sys/class/drm/card0"})
	b.PutFile(devPath+"/vendor", []byte("0x1002\n"))
	b.PutFile(devPath+"/gpu_busy_percent", []byte("10\n"))
	b.PutFile(devPath+"/mem_info_vram_used", []byte("0\n"))
	b.PutFile(devPath+"/mem_info_vram_total", []byte("0\n"))
	b.PutFile(devPath+"/mem_info_gtt_total", []byte(""))
	b.PutFile(devPath+"/uevent", []byte(""))
	b.PutCmdNotFound("nvidia-smi",
		[]string{
			"--query-gpu=index,name,temperature.gpu,utilization.gpu,memory.used,memory.total,power.draw,driver_version,power.limit",
			"--format=csv,noheader,nounits",
		})
	b.PutCmd("glxinfo", []string{"-B"},
		"OpenGL version string: 4.6 (Compatibility Profile) Mesa 24.3.1\n", 0)
	prev := SetSource(&fakeReadlinkSource{Replay: source.NewReplay(b), links: links})
	t.Cleanup(func() { SetSource(prev) })

	got, err := NewGPUCollector().Collect(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	info := got.(*models.GPUInfo)
	if len(info.Devices) != 1 {
		t.Fatalf("got %d devices, want 1", len(info.Devices))
	}
	if info.Devices[0].MesaVersion != "24.3.1" {
		t.Errorf("MesaVersion = %q, want 24.3.1 (applied from detectMesaVersion)", info.Devices[0].MesaVersion)
	}
}

// TestGPUCollector_Collect_NvidiaNoDriver drives the nvidia-smi-unavailable
// fallback: a bus-detected NVIDIA card whose driver is nouveau.
func TestGPUCollector_Collect_NvidiaNoDriver(t *testing.T) {
	t.Setenv("DISPLAY", "")
	t.Setenv("WAYLAND_DISPLAY", "")
	withFixtureSource(t, func(b *source.Bundle) {
		b.PutGlob("/sys/class/drm/card[0-9]", []string{"/sys/class/drm/card0"})
		devPath := "/sys/class/drm/card0/device"
		b.PutFile(devPath+"/vendor", []byte("0x10de\n"))
		b.PutFile(devPath+"/uevent", []byte("DRIVER=nouveau\nPCI_ID=10de:2684\n"))
		b.PutCmdNotFound("nvidia-smi",
			[]string{
				"--query-gpu=index,name,temperature.gpu,utilization.gpu,memory.used,memory.total,power.draw,driver_version,power.limit",
				"--format=csv,noheader,nounits",
			})
	})
	got, err := NewGPUCollector().Collect(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	info := got.(*models.GPUInfo)
	if info.Status != "nvidia-no-driver" {
		t.Errorf("Status = %q, want nvidia-no-driver", info.Status)
	}
	if len(info.NoDriver) != 1 || info.NoDriver[0].Name != "NVIDIA GPU (2684) [nouveau]" {
		t.Errorf("NoDriver = %+v", info.NoDriver)
	}
}

// TestGPUCollector_Collect_AMDPath drives the full AMD sysfs path through
// Collect(), including the real 1-second busy-percent sampler.
func TestGPUCollector_Collect_AMDPath(t *testing.T) {
	t.Setenv("DISPLAY", "")
	t.Setenv("WAYLAND_DISPLAY", "")
	links := map[string]string{
		"/sys/class/drm/card0/device/driver": "../../../bus/pci/drivers/amdgpu",
	}
	b := source.NewBundle()
	devPath := "/sys/class/drm/card0/device"
	b.PutGlob("/sys/class/drm/card[0-9]", []string{"/sys/class/drm/card0"})
	b.PutFile(devPath+"/vendor", []byte("0x1002\n"))
	b.PutFile(devPath+"/gpu_busy_percent", []byte("10\n"))
	b.PutFile(devPath+"/mem_info_vram_used", []byte("0\n"))
	b.PutFile(devPath+"/mem_info_vram_total", []byte("0\n"))
	b.PutFile(devPath+"/mem_info_gtt_total", []byte(""))
	b.PutFile(devPath+"/uevent", []byte(""))
	b.PutCmdNotFound("nvidia-smi",
		[]string{
			"--query-gpu=index,name,temperature.gpu,utilization.gpu,memory.used,memory.total,power.draw,driver_version,power.limit",
			"--format=csv,noheader,nounits",
		})
	prev := SetSource(&fakeReadlinkSource{Replay: source.NewReplay(b), links: links})
	t.Cleanup(func() { SetSource(prev) })

	got, err := NewGPUCollector().Collect(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	info := got.(*models.GPUInfo)
	if len(info.Devices) != 1 {
		t.Fatalf("got %d devices, want 1", len(info.Devices))
	}
	dev := info.Devices[0]
	// The base gpu_busy_percent (10) read during collectAMDGPUs must have been
	// overridden by the 1s post-sleep instantaneous sample from the same file.
	if dev.UtilPct != 10 {
		t.Errorf("UtilPct = %d, want 10 (from the busy sampler)", dev.UtilPct)
	}
}

// TestSampleAMDBusy_ReadsBothPercentages drives sampleAMDBusy directly
// (bypassing Collect's goroutine plumbing) to cover both the successful
// gpu_busy_percent/mem_busy_percent parse and the absent/unreadable ->
// sentinel -1 branch, across two cards in the same call.
func TestSampleAMDBusy_ReadsBothPercentages(t *testing.T) {
	withFixtureSource(t, func(b *source.Bundle) {
		b.PutFile("/sys/class/drm/card0/device/gpu_busy_percent", []byte("42\n"))
		b.PutFile("/sys/class/drm/card0/device/mem_busy_percent", []byte("17\n"))
		// card1: neither file seeded -> readSysfsStr returns "" -> sentinel -1.
	})
	ch := make(chan []busySample, 1)
	sampleAMDBusy(context.Background(), []string{"/sys/class/drm/card0", "/sys/class/drm/card1"}, ch)
	samples := <-ch
	if len(samples) != 2 {
		t.Fatalf("got %d samples, want 2", len(samples))
	}
	if samples[0].gpuBusy != 42 || samples[0].memBusy != 17 {
		t.Errorf("card0 = %+v, want gpuBusy=42 memBusy=17", samples[0])
	}
	if samples[1].gpuBusy != -1 || samples[1].memBusy != -1 {
		t.Errorf("card1 = %+v, want both sentinel -1 (files absent)", samples[1])
	}
}

// TestGPUCollector_Collect_ContextCancelled exercises the <-ctx.Done() branch
// of the busy-sample select: a context cancelled before the 1s sampler
// completes must not block Collect().
func TestGPUCollector_Collect_ContextCancelled(t *testing.T) {
	t.Setenv("DISPLAY", "")
	t.Setenv("WAYLAND_DISPLAY", "")
	links := map[string]string{
		"/sys/class/drm/card0/device/driver": "../../../bus/pci/drivers/amdgpu",
	}
	b := source.NewBundle()
	devPath := "/sys/class/drm/card0/device"
	b.PutGlob("/sys/class/drm/card[0-9]", []string{"/sys/class/drm/card0"})
	b.PutFile(devPath+"/vendor", []byte("0x1002\n"))
	b.PutFile(devPath+"/gpu_busy_percent", []byte("10\n"))
	b.PutFile(devPath+"/mem_info_vram_used", []byte("0\n"))
	b.PutFile(devPath+"/mem_info_vram_total", []byte("0\n"))
	b.PutFile(devPath+"/mem_info_gtt_total", []byte(""))
	b.PutFile(devPath+"/uevent", []byte(""))
	b.PutCmdNotFound("nvidia-smi",
		[]string{
			"--query-gpu=index,name,temperature.gpu,utilization.gpu,memory.used,memory.total,power.draw,driver_version,power.limit",
			"--format=csv,noheader,nounits",
		})
	prev := SetSource(&fakeReadlinkSource{Replay: source.NewReplay(b), links: links})
	t.Cleanup(func() { SetSource(prev) })

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	got, err := NewGPUCollector().Collect(ctx)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	info := got.(*models.GPUInfo)
	if len(info.Devices) != 1 {
		t.Fatalf("got %d devices, want 1", len(info.Devices))
	}
	// Collect() returns as soon as ctx.Done() fires, but sampleAMDBusy's
	// goroutine keeps running for its full 1s sleep in the background. Wait it
	// out here, while our fixture source is still active, so it doesn't read
	// through activeSource after t.Cleanup swaps the global back — a data race
	// against whatever source a later test installs.
	time.Sleep(1100 * time.Millisecond)
}

// TestCollectIntelGPUs_GlobError covers gpu_linux.go:414.16,416.3 — the early
// nil return when glob fails. With a Replay source that has no DRM card glob
// seeded, Glob returns ErrNotRecorded and collectIntelGPUs returns nil.
func TestCollectIntelGPUs_GlobError(t *testing.T) {
	// No t.Parallel(): withFixtureSource swaps the package-global source.
	withFixtureSource(t, func(b *source.Bundle) {
		// gpuDRMCardGlob ("/sys/class/drm/card[0-9]") is not seeded →
		// Replay.Glob returns ErrNotRecorded → collectIntelGPUs returns nil.
	})
	if got := collectIntelGPUs(); got != nil {
		t.Errorf("expected nil devices when glob returns error, got %v", got)
	}
}
