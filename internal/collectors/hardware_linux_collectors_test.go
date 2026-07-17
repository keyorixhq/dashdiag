//go:build linux

package collectors

import (
	"context"
	"testing"
	"time"

	"github.com/keyorixhq/dashdiag/internal/models"
	"github.com/keyorixhq/dashdiag/internal/source"
)

func TestHardwareCollectorIdentity(t *testing.T) {
	c := NewHardwareCollector()
	if c == nil {
		t.Fatal("NewHardwareCollector returned nil")
	}
	if c.Name() != "Hardware" {
		t.Errorf("Name() = %q, want Hardware", c.Name())
	}
	if c.Timeout() != 15*time.Second {
		t.Errorf("Timeout() = %v, want 15s", c.Timeout())
	}
}

const smartctlScanJSON = `{"devices":[{"name":"/dev/nvme0","info_name":"/dev/nvme0","type":"nvme","protocol":"NVMe"}]}`

const smartctlNVMeJSON = `{
	"model_name": "Samsung SSD 980",
	"device": {"type": "nvme", "protocol": "NVMe"},
	"smart_status": {"passed": true},
	"temperature": {"current": 38},
	"power_on_time": {"hours": 1200},
	"power_cycle_count": 42,
	"nvme_smart_health_information_log": {"percentage_used": 5, "media_errors": 0, "unsafe_shutdowns": 2}
}`

// TestHardwareCollector_Collect_FullHappyPath drives the entire Collect()
// pipeline: system identity, CPU, RAM slots, one NVMe SMART drive, hwmon
// thermals, EDAC, and one physical NIC.
func TestHardwareCollector_Collect_FullHappyPath(t *testing.T) {
	withReadlinkFixture(t, map[string]string{
		"/sys/class/net/eth0/device/driver": "/sys/bus/pci/drivers/e1000e",
	}, func(b *source.Bundle) {
		b.PutFile("/sys/class/dmi/id/sys_vendor", []byte("Dell Inc.\n"))
		b.PutFile("/sys/class/dmi/id/product_name", []byte("PowerEdge R740\n"))
		b.PutFile("/sys/class/dmi/id/board_name", []byte("0ABCD1\n"))

		b.PutFile("/proc/cpuinfo", []byte("processor\t: 0\nmodel name\t: Xeon Gold 6230\ncpu cores\t: 2\ncpu MHz\t: 2100.000\n\nprocessor\t: 1\nmodel name\t: Xeon Gold 6230\ncpu cores\t: 2\ncpu MHz\t: 2100.000\n"))
		b.PutFile("/sys/devices/system/cpu/cpu0/cpufreq/cpuinfo_max_freq", []byte("3900000\n"))
		b.PutFile("/proc/loadavg", []byte("1.00 0.50 0.25 1/200 12345\n"))

		b.PutCmd("dmidecode", []string{"-t", "memory"}, dmidecodeMemoryOutput, 0)

		b.PutCmd("smartctl", []string{"--scan-open", "--json=c"}, smartctlScanJSON, 0)
		b.PutCmd("smartctl", []string{"--json=c", "-a", "/dev/nvme0"}, smartctlNVMeJSON, 0)

		b.PutDir("/sys/class/hwmon", []string{"hwmon0"})
		b.PutFile("/sys/class/hwmon/hwmon0/name", []byte("coretemp\n"))
		b.PutGlob("/sys/class/hwmon/hwmon0/temp*_input", []string{"/sys/class/hwmon/hwmon0/temp1_input"})
		b.PutFile("/sys/class/hwmon/hwmon0/temp1_input", []byte("45000\n"))
		b.PutFile("/sys/class/hwmon/hwmon0/temp1_label", []byte("Package id 0\n"))

		b.PutDir("/sys/devices/system/edac/mc", []string{"mc0"})
		b.PutStat("/sys/devices/system/edac/mc/mc0/ce_count", source.FileMeta{})
		b.PutFile("/sys/devices/system/edac/mc/mc0/ce_count", []byte("3\n"))
		b.PutFile("/sys/devices/system/edac/mc/mc0/ue_count", []byte("0\n"))

		b.PutDir("/sys/class/net", []string{"lo", "eth0"})
		b.PutFile("/sys/class/net/eth0/address", []byte("aa:bb:cc:dd:ee:ff\n"))
		b.PutFile("/sys/class/net/eth0/operstate", []byte("up\n"))
		b.PutFile("/sys/class/net/eth0/speed", []byte("1000\n"))
		b.PutFile("/sys/class/net/eth0/statistics/rx_errors", []byte("0\n"))
		b.PutFile("/sys/class/net/eth0/statistics/tx_errors", []byte("2\n"))
	})

	c := NewHardwareCollector()
	raw, err := c.Collect(context.Background())
	if err != nil {
		t.Fatalf("Collect() error: %v", err)
	}
	info := raw.(*models.HardwareInfo)

	if info.System.Vendor != "Dell Inc." || info.System.Model != "PowerEdge R740" || info.System.Board != "0ABCD1" {
		t.Errorf("System = %+v, unexpected", info.System)
	}
	if info.CPU.Model != "Xeon Gold 6230" || info.CPU.Cores != 2 || info.CPU.Threads != 2 {
		t.Errorf("CPU = %+v, unexpected model/cores/threads", info.CPU)
	}
	if info.CPU.MaxFreqMHz != 3900 {
		t.Errorf("CPU.MaxFreqMHz = %v, want 3900", info.CPU.MaxFreqMHz)
	}
	if info.Memory.TotalGB != 32 || len(info.Memory.Slots) != 1 {
		t.Errorf("Memory = %+v, want TotalGB=32 with 1 slot", info.Memory)
	}
	if !info.Memory.EDACAvailable || info.Memory.CorrectedErrors != 3 {
		t.Errorf("Memory EDAC = available=%v corrected=%d, want true/3", info.Memory.EDACAvailable, info.Memory.CorrectedErrors)
	}
	if len(info.Drives) != 1 || info.Drives[0].Model != "Samsung SSD 980" || !info.Drives[0].SmartOK {
		t.Errorf("Drives = %+v, unexpected", info.Drives)
	}
	if len(info.Thermals) != 1 || info.Thermals[0].TempC != 45 || info.Thermals[0].Label != "Package id 0" {
		t.Errorf("Thermals = %+v, unexpected", info.Thermals)
	}
	if len(info.NICs) != 1 || info.NICs[0].Name != "eth0" || info.NICs[0].Driver != "e1000e" || info.NICs[0].SpeedMbps != 1000 {
		t.Errorf("NICs = %+v, unexpected", info.NICs)
	}
}

func TestCollectSMARTDrives_SmartctlNotInstalled(t *testing.T) {
	withFixtureSource(t, func(b *source.Bundle) {
		b.PutCmdNotFound("smartctl", []string{"--scan-open", "--json=c"})
	})
	info := &models.HardwareInfo{}
	collectSMARTDrives(context.Background(), info)
	if len(info.Drives) != 1 || info.Drives[0].SmartctlAvailable || info.Drives[0].Error == "" {
		t.Errorf("Drives = %+v, want one placeholder drive with SmartctlAvailable=false", info.Drives)
	}
}

func TestCollectSMARTDrives_NoDevicesFound(t *testing.T) {
	withFixtureSource(t, func(b *source.Bundle) {
		b.PutCmd("smartctl", []string{"--scan-open", "--json=c"}, `{"devices":[]}`, 0)
	})
	info := &models.HardwareInfo{}
	collectSMARTDrives(context.Background(), info)
	if len(info.Drives) != 0 {
		t.Errorf("Drives = %+v, want none when scan reports no devices", info.Drives)
	}
}

func TestCollectSMARTDrives_ScanUnparseable(t *testing.T) {
	withFixtureSource(t, func(b *source.Bundle) {
		b.PutCmd("smartctl", []string{"--scan-open", "--json=c"}, "not json", 0)
	})
	info := &models.HardwareInfo{}
	collectSMARTDrives(context.Background(), info)
	if len(info.Drives) != 0 {
		t.Errorf("Drives = %+v, want none when scan JSON is unparseable", info.Drives)
	}
}

// TestCollectOneDrive_NonZeroExit covers the "ran but failed" branch reached via
// the fixture harness. The "needs root" hint text specifically matches Go's raw
// os/exec ExitError string ("exit status 1/2"), which only a genuine live
// subprocess produces — Replay.Run returns a nil error for any recorded exit
// code (runCmd wraps it in its own cmdError, "<name> exited <code>"), so that
// exact branch is not reachable through this fixture path. This still exercises
// the err!=nil / out=="" generic-failure branch, just not the root-hint text.
func TestCollectOneDrive_NonZeroExit(t *testing.T) {
	withFixtureSource(t, func(b *source.Bundle) {
		b.PutCmd("smartctl", []string{"--json=c", "-a", "/dev/sda"}, "", 1)
	})
	drive := collectOneDrive(context.Background(), "/dev/sda")
	if drive.Error == "" {
		t.Error("Error = \"\", want a failure message set")
	}
}

func TestCollectOneDrive_JSONParseError(t *testing.T) {
	withFixtureSource(t, func(b *source.Bundle) {
		b.PutCmd("smartctl", []string{"--json=c", "-a", "/dev/sda"}, "not json", 0)
	})
	drive := collectOneDrive(context.Background(), "/dev/sda")
	if drive.Error == "" {
		t.Error("Error = \"\", want a JSON-parse-error message")
	}
}

func TestCollectOneDrive_NVMe(t *testing.T) {
	withFixtureSource(t, func(b *source.Bundle) {
		b.PutCmd("smartctl", []string{"--json=c", "-a", "/dev/nvme0"}, smartctlNVMeJSON, 0)
	})
	drive := collectOneDrive(context.Background(), "/dev/nvme0")
	if drive.Type != "nvme" || drive.Model != "Samsung SSD 980" || !drive.SmartRead || !drive.SmartOK {
		t.Errorf("drive = %+v, unexpected", drive)
	}
	if drive.TempC != 38 || drive.PowerOnH != 1200 {
		t.Errorf("TempC/PowerOnH = %d/%d, want 38/1200", drive.TempC, drive.PowerOnH)
	}
	if drive.WearPct != 5 || drive.MediaErrors != 0 || drive.UnsafeShutdowns != 2 {
		t.Errorf("WearPct/MediaErrors/UnsafeShutdowns = %d/%d/%d, want 5/0/2", drive.WearPct, drive.MediaErrors, drive.UnsafeShutdowns)
	}
}

const smartctlSATAJSON = `{
	"model_name": "WDC WD40",
	"device": {"type": "sat", "protocol": "ATA"},
	"smart_status": {"passed": false},
	"temperature": {"current": 0},
	"ata_smart_attributes": {"table": [
		{"id": 5, "name": "Reallocated_Sector_Ct", "value": 100, "raw": {"value": 3}},
		{"id": 194, "name": "Temperature_Celsius", "value": 60, "raw": {"value": 42}},
		{"id": 197, "name": "Current_Pending_Sector", "value": 100, "raw": {"value": 1}},
		{"id": 198, "name": "Offline_Uncorrectable", "value": 100, "raw": {"value": 2}},
		{"id": 231, "name": "SSD_Life_Left", "value": 90, "raw": {"value": 999999}}
	]}
}`

func TestCollectOneDrive_SATA(t *testing.T) {
	withFixtureSource(t, func(b *source.Bundle) {
		b.PutCmd("smartctl", []string{"--json=c", "-a", "/dev/sda"}, smartctlSATAJSON, 0)
	})
	drive := collectOneDrive(context.Background(), "/dev/sda")
	if drive.Type != "sata" || drive.SmartRead != true || drive.SmartOK != false {
		t.Errorf("drive = %+v, unexpected type/smart", drive)
	}
	if drive.ReallocatedSectors != 3 {
		t.Errorf("ReallocatedSectors = %d, want 3", drive.ReallocatedSectors)
	}
	if drive.TempC != 42 {
		t.Errorf("TempC = %d, want 42 (from attribute 194, since JSON temperature.current is 0)", drive.TempC)
	}
	if drive.PendingSectors != 1 {
		t.Errorf("PendingSectors = %d, want 1", drive.PendingSectors)
	}
	if drive.UncorrectableErrors != 2 {
		t.Errorf("UncorrectableErrors = %d, want 2", drive.UncorrectableErrors)
	}
	if drive.WearPct != 10 {
		t.Errorf("WearPct = %d, want 10 (100 - normalised value 90)", drive.WearPct)
	}
}

func TestCollectOneDrive_WearGuardsNonNormalisedValue(t *testing.T) {
	// attr.Value > 100 must NOT be treated as a normalised remaining-life percentage.
	out := `{"model_name":"x","device":{"protocol":"ATA"},"ata_smart_attributes":{"table":[
		{"id": 173, "value": 3491877946276, "raw": {"value": 3491877946276}}
	]}}`
	withFixtureSource(t, func(b *source.Bundle) {
		b.PutCmd("smartctl", []string{"--json=c", "-a", "/dev/sda"}, out, 0)
	})
	drive := collectOneDrive(context.Background(), "/dev/sda")
	if drive.WearPct != 0 {
		t.Errorf("WearPct = %d, want 0 (non-normalised value must be rejected)", drive.WearPct)
	}
}

func TestCollectHwmonThermals_MultipleSensors(t *testing.T) {
	withFixtureSource(t, func(b *source.Bundle) {
		b.PutDir("/sys/class/hwmon", []string{"hwmon0", "hwmon1"})
		b.PutFile("/sys/class/hwmon/hwmon0/name", []byte("coretemp\n"))
		b.PutGlob("/sys/class/hwmon/hwmon0/temp*_input", []string{"/sys/class/hwmon/hwmon0/temp1_input"})
		b.PutFile("/sys/class/hwmon/hwmon0/temp1_input", []byte("52000\n"))
		// no label file for hwmon0/temp1 -> falls back to the base name.
		b.PutFile("/sys/class/hwmon/hwmon1/name", []byte("acpitz\n")) // not CPU/drive -> skipped
	})
	info := &models.HardwareInfo{}
	collectHwmonThermals(info)
	if len(info.Thermals) != 1 {
		t.Fatalf("Thermals = %+v, want 1 entry (acpitz must be skipped)", info.Thermals)
	}
	if info.Thermals[0].TempC != 52 || info.Thermals[0].Label != "temp1" {
		t.Errorf("Thermals[0] = %+v, want TempC=52 Label=temp1 (no label file -> base name)", info.Thermals[0])
	}
}

func TestCollectHwmonThermals_NoHwmonDir(t *testing.T) {
	withFixtureSource(t, func(b *source.Bundle) {})
	info := &models.HardwareInfo{}
	collectHwmonThermals(info)
	if len(info.Thermals) != 0 {
		t.Errorf("Thermals = %+v, want none when hwmon dir is absent", info.Thermals)
	}
}

// TestCollectHwmonThermals_NameFileUnreadableSkipped guards the "name" read
// error branch: a hwmon entry whose name file can't be read must be skipped
// entirely, not panic or produce a zero-value sensor.
func TestCollectHwmonThermals_NameFileUnreadableSkipped(t *testing.T) {
	withFixtureSource(t, func(b *source.Bundle) {
		b.PutDir("/sys/class/hwmon", []string{"hwmon0"})
		// no name file seeded for hwmon0 -> readFile errors
	})
	info := &models.HardwareInfo{}
	collectHwmonThermals(info)
	if len(info.Thermals) != 0 {
		t.Errorf("Thermals = %+v, want none when name file is unreadable", info.Thermals)
	}
}

// TestCollectHwmonThermals_NonNumericTempSkipped guards the Atoi-error branch
// on a temp*_input file: a garbled reading must be skipped, not zero-valued.
func TestCollectHwmonThermals_NonNumericTempSkipped(t *testing.T) {
	withFixtureSource(t, func(b *source.Bundle) {
		b.PutDir("/sys/class/hwmon", []string{"hwmon0"})
		b.PutFile("/sys/class/hwmon/hwmon0/name", []byte("k10temp\n"))
		b.PutGlob("/sys/class/hwmon/hwmon0/temp*_input", []string{"/sys/class/hwmon/hwmon0/temp1_input"})
		b.PutFile("/sys/class/hwmon/hwmon0/temp1_input", []byte("not-a-number\n"))
	})
	info := &models.HardwareInfo{}
	collectHwmonThermals(info)
	if len(info.Thermals) != 0 {
		t.Errorf("Thermals = %+v, want none for a non-numeric temp reading", info.Thermals)
	}
}

// TestCollectHwmonThermals_LabelFilePresent guards the labelled-sensor branch
// (label file present overrides the base-name fallback) across multiple
// temp*_input files on the same drivetemp sensor.
func TestCollectHwmonThermals_LabelFilePresent(t *testing.T) {
	withFixtureSource(t, func(b *source.Bundle) {
		b.PutDir("/sys/class/hwmon", []string{"hwmon0"})
		b.PutFile("/sys/class/hwmon/hwmon0/name", []byte("drivetemp\n"))
		b.PutGlob("/sys/class/hwmon/hwmon0/temp*_input", []string{
			"/sys/class/hwmon/hwmon0/temp1_input",
			"/sys/class/hwmon/hwmon0/temp2_input",
		})
		b.PutFile("/sys/class/hwmon/hwmon0/temp1_input", []byte("45000\n"))
		b.PutFile("/sys/class/hwmon/hwmon0/temp1_label", []byte("Composite\n"))
		b.PutFile("/sys/class/hwmon/hwmon0/temp2_input", []byte("50000\n"))
		// no label file for temp2 -> falls back to base name
	})
	info := &models.HardwareInfo{}
	collectHwmonThermals(info)
	if len(info.Thermals) != 2 {
		t.Fatalf("Thermals = %+v, want 2 entries", info.Thermals)
	}
	byLabel := map[string]int{}
	for _, th := range info.Thermals {
		byLabel[th.Label] = th.TempC
	}
	if byLabel["Composite"] != 45 {
		t.Errorf("Composite temp = %d, want 45", byLabel["Composite"])
	}
	if byLabel["temp2"] != 50 {
		t.Errorf("temp2 (fallback label) = %d, want 50", byLabel["temp2"])
	}
}

func TestCollectEDAC(t *testing.T) {
	withFixtureSource(t, func(b *source.Bundle) {
		b.PutDir("/sys/devices/system/edac/mc", []string{"mc0"})
		b.PutStat("/sys/devices/system/edac/mc/mc0/ce_count", source.FileMeta{})
		b.PutFile("/sys/devices/system/edac/mc/mc0/ce_count", []byte("7\n"))
		b.PutFile("/sys/devices/system/edac/mc/mc0/ue_count", []byte("1\n"))
	})
	info := &models.HardwareInfo{}
	collectEDAC(info)
	if !info.Memory.EDACAvailable || info.Memory.CorrectedErrors != 7 || info.Memory.UncorrectedErrors != 1 {
		t.Errorf("Memory = %+v, want available=true corrected=7 uncorrected=1", info.Memory)
	}
}

func TestCollectEDAC_Absent(t *testing.T) {
	withFixtureSource(t, func(b *source.Bundle) {})
	info := &models.HardwareInfo{}
	collectEDAC(info)
	if info.Memory.EDACAvailable {
		t.Error("EDACAvailable = true, want false when EDAC sysfs is absent")
	}
}

func TestCollectCPU_X86(t *testing.T) {
	withFixtureSource(t, func(b *source.Bundle) {
		b.PutFile("/proc/cpuinfo", []byte("processor\t: 0\nmodel name\t: Xeon Gold 6230\ncpu cores\t: 4\ncpu MHz\t: 2100.500\n"))
		b.PutFile("/sys/devices/system/cpu/cpu0/cpufreq/cpuinfo_max_freq", []byte("3900000\n"))
		b.PutFile("/proc/loadavg", []byte("2.0 1.0 0.5 1/300 999\n"))
	})
	info := &models.HardwareInfo{}
	collectCPU(info)
	if info.CPU.Model != "Xeon Gold 6230" || info.CPU.Cores != 4 || info.CPU.Threads != 1 {
		t.Errorf("CPU = %+v, unexpected", info.CPU)
	}
	if info.CPU.FreqMHz != 2100.5 {
		t.Errorf("FreqMHz = %v, want 2100.5", info.CPU.FreqMHz)
	}
	if info.CPU.MaxFreqMHz != 3900 {
		t.Errorf("MaxFreqMHz = %v, want 3900", info.CPU.MaxFreqMHz)
	}
	if info.CPU.LoadPct != 200 {
		t.Errorf("LoadPct = %v, want 200 (load1=2.0 / 1 thread * 100)", info.CPU.LoadPct)
	}
}

func TestCollectCPU_ARMDeviceTreeFallback(t *testing.T) {
	withFixtureSource(t, func(b *source.Bundle) {
		// No model name / Hardware / implementer -> falls back to device-tree model.
		b.PutFile("/proc/cpuinfo", []byte("processor\t: 0\n"))
		b.PutFile("/sys/firmware/devicetree/base/model", []byte("Raspberry Pi 4 Model B Rev 1.4\x00"))
		b.PutFile("/sys/devices/system/cpu/cpu0/cpufreq/scaling_cur_freq", []byte("1500000\n"))
	})
	info := &models.HardwareInfo{}
	collectCPU(info)
	if info.CPU.Model != "Raspberry Pi 4 Model B Rev 1.4" {
		t.Errorf("Model = %q, want the device-tree model", info.CPU.Model)
	}
	if info.CPU.FreqMHz != 1500 {
		t.Errorf("FreqMHz = %v, want 1500 (from scaling_cur_freq fallback)", info.CPU.FreqMHz)
	}
}

func TestCollectCPU_CPUInfoUnreadable(t *testing.T) {
	withFixtureSource(t, func(b *source.Bundle) {})
	info := &models.HardwareInfo{}
	collectCPU(info)
	if info.CPU.Model != "" || info.CPU.Threads != 0 {
		t.Errorf("CPU = %+v, want zero value when /proc/cpuinfo is unreadable", info.CPU)
	}
}

func TestCollectSystem(t *testing.T) {
	withFixtureSource(t, func(b *source.Bundle) {
		b.PutFile("/sys/class/dmi/id/sys_vendor", []byte("Lenovo\n"))
		b.PutFile("/sys/class/dmi/id/product_name", []byte("ThinkPad X1\n"))
		// board_name intentionally unseeded -> "".
	})
	info := &models.HardwareInfo{}
	collectSystem(info)
	if info.System.Vendor != "Lenovo" || info.System.Model != "ThinkPad X1" || info.System.Board != "" {
		t.Errorf("System = %+v, unexpected", info.System)
	}
}

const dmidecodeMemoryOutput = `# dmidecode 3.3
Handle 0x0011, DMI type 17, 40 bytes
Memory Device
	Array Handle: 0x0010
	Error Information Handle: Not Provided
	Total Width: 72 bits
	Data Width: 64 bits
	Size: 32 GB
	Form Factor: DIMM
	Set: None
	Locator: DIMM_A1
	Bank Locator: BANK 0
	Type: DDR4
	Type Detail: Synchronous
	Speed: 3200 MT/s
	Configured Memory Speed: 3200 MT/s
Handle 0x0012, DMI type 17, 40 bytes
Memory Device
	Array Handle: 0x0010
	Error Information Handle: Not Provided
	Total Width: Unknown
	Data Width: Unknown
	Size: No Module Installed
	Form Factor: DIMM
	Set: None
	Locator: DIMM_A2
	Bank Locator: BANK 1
	Type: Unknown
`

func TestCollectRAM(t *testing.T) {
	withFixtureSource(t, func(b *source.Bundle) {
		b.PutCmd("dmidecode", []string{"-t", "memory"}, dmidecodeMemoryOutput, 0)
	})
	info := &models.HardwareInfo{}
	collectRAM(context.Background(), info)
	if info.Memory.TotalGB != 32 {
		t.Errorf("TotalGB = %v, want 32 (empty slot must be excluded)", info.Memory.TotalGB)
	}
	if len(info.Memory.Slots) != 1 {
		t.Fatalf("Slots = %+v, want 1", info.Memory.Slots)
	}
	s := info.Memory.Slots[0]
	if s.Locator != "DIMM_A1" || s.Type != "DDR4" || s.SpeedMT != 3200 || s.SizeGB != 32 {
		t.Errorf("Slots[0] = %+v, unexpected", s)
	}
}

func TestCollectRAM_MBSize(t *testing.T) {
	withFixtureSource(t, func(b *source.Bundle) {
		b.PutCmd("dmidecode", []string{"-t", "memory"},
			"Memory Device\n\tSize: 512 MB\n\tLocator: DIMM_0\n\tType: DDR3\n", 0)
	})
	info := &models.HardwareInfo{}
	collectRAM(context.Background(), info)
	if len(info.Memory.Slots) != 1 || info.Memory.Slots[0].SizeGB != 0.5 {
		t.Errorf("Slots = %+v, want 1 slot of 0.5 GB", info.Memory.Slots)
	}
}

func TestCollectRAM_DmidecodeUnavailable(t *testing.T) {
	withFixtureSource(t, func(b *source.Bundle) {
		b.PutCmdNotFound("dmidecode", []string{"-t", "memory"})
	})
	info := &models.HardwareInfo{}
	collectRAM(context.Background(), info)
	if info.Memory.TotalGB != 0 || info.Memory.Slots != nil {
		t.Errorf("Memory = %+v, want zero value when dmidecode is unavailable", info.Memory)
	}
}

func TestCollectNICs_PhysicalOnly(t *testing.T) {
	withReadlinkFixture(t, map[string]string{
		"/sys/class/net/eth0/device/driver": "/sys/bus/pci/drivers/e1000e",
	}, func(b *source.Bundle) {
		b.PutDir("/sys/class/net", []string{"lo", "eth0", "veth1234", "docker0", "bonding_masters"})
		b.PutFile("/sys/class/net/eth0/address", []byte("aa:bb:cc:dd:ee:ff\n"))
		b.PutFile("/sys/class/net/eth0/operstate", []byte("up\n"))
		b.PutFile("/sys/class/net/eth0/speed", []byte("1000\n"))
		b.PutFile("/sys/class/net/eth0/statistics/rx_errors", []byte("3\n"))
		b.PutFile("/sys/class/net/eth0/statistics/tx_errors", []byte("4\n"))
	})
	info := &models.HardwareInfo{}
	collectNICs(context.Background(), info)
	if len(info.NICs) != 1 {
		t.Fatalf("NICs = %+v, want only eth0 (lo/veth/docker/bonding_masters excluded)", info.NICs)
	}
	nic := info.NICs[0]
	if nic.Name != "eth0" || nic.MAC != "aa:bb:cc:dd:ee:ff" || nic.State != "up" || nic.SpeedMbps != 1000 ||
		nic.Driver != "e1000e" || nic.RxErrors != 3 || nic.TxErrors != 4 {
		t.Errorf("NICs[0] = %+v, unexpected", nic)
	}
}

func TestCollectNICs_UnknownOperstateFallsBackToCarrier(t *testing.T) {
	withReadlinkFixture(t, nil, func(b *source.Bundle) {
		b.PutDir("/sys/class/net", []string{"tap101i0"})
		b.PutFile("/sys/class/net/tap101i0/operstate", []byte("unknown\n"))
		b.PutFile("/sys/class/net/tap101i0/carrier", []byte("1\n"))
	})
	info := &models.HardwareInfo{}
	collectNICs(context.Background(), info)
	if len(info.NICs) != 1 || info.NICs[0].State != "up" {
		t.Errorf("NICs = %+v, want tap101i0 State=up via carrier fallback", info.NICs)
	}
}

func TestCollectNICs_NoNetDir(t *testing.T) {
	withFixtureSource(t, func(b *source.Bundle) {})
	info := &models.HardwareInfo{}
	collectNICs(context.Background(), info)
	if info.NICs != nil {
		t.Errorf("NICs = %v, want nil when /sys/class/net is absent", info.NICs)
	}
}

const smartctlSASJSON = `{"model_name":"ST4000NM0025","device":{"type":"scsi","protocol":"SAS"},"smart_status":{"passed":true},"temperature":{"current":30}}`

// TestCollectOneDrive_SAS covers hardware_linux.go:150.73,151.21 — the SAS/SCSI
// drive-type case in getSmartctlDriveInfo's protocol switch.
func TestCollectOneDrive_SAS(t *testing.T) {
	withFixtureSource(t, func(b *source.Bundle) {
		b.PutCmd("smartctl", []string{"--json=c", "-a", "/dev/sdb"}, smartctlSASJSON, 0)
	})
	drive := collectOneDrive(context.Background(), "/dev/sdb")
	if drive.Type != "sas" {
		t.Errorf("Type = %q, want %q (SCSI/SAS protocol → sas)", drive.Type, "sas")
	}
}

const smartctlUnknownProtoJSON = `{"model_name":"FC-Drive-X","device":{"type":"fc","protocol":"Fibre Channel"},"smart_status":{"passed":true},"temperature":{"current":25}}`

// TestCollectOneDrive_UnknownProtocol covers hardware_linux.go:152.10,153.33 — the
// default case in the protocol switch (drive.Type = d.Device.Protocol verbatim).
func TestCollectOneDrive_UnknownProtocol(t *testing.T) {
	withFixtureSource(t, func(b *source.Bundle) {
		b.PutCmd("smartctl", []string{"--json=c", "-a", "/dev/sdc"}, smartctlUnknownProtoJSON, 0)
	})
	drive := collectOneDrive(context.Background(), "/dev/sdc")
	if drive.Type != "Fibre Channel" {
		t.Errorf("Type = %q, want %q (unknown protocol falls through to default)", drive.Type, "Fibre Channel")
	}
}

const smartctlSATAWearAttr173JSON = `{"model_name":"Samsung SSD 870","device":{"type":"sat","protocol":"ATA"},"smart_status":{"passed":true},"temperature":{"current":0},"ata_smart_attributes":{"table":[{"id":173,"name":"Wear_Leveling_Count","value":85,"raw":{"value":0}}]}}`

// TestCollectOneDrive_Attr173WearLevel covers hardware_linux.go:173.66,175.6 — the
// then-branch of the attr-173/177 wear guard when value is normalised (1–100).
// Complementary to TestCollectOneDrive_WearGuardsNonNormalisedValue which proves
// a value > 100 is rejected.
func TestCollectOneDrive_Attr173WearLevel(t *testing.T) {
	withFixtureSource(t, func(b *source.Bundle) {
		b.PutCmd("smartctl", []string{"--json=c", "-a", "/dev/sdd"}, smartctlSATAWearAttr173JSON, 0)
	})
	drive := collectOneDrive(context.Background(), "/dev/sdd")
	if drive.WearPct != 15 { // 100 - attr.Value(85)
		t.Errorf("WearPct = %d, want 15 (100 - normalised attr-173 value 85)", drive.WearPct)
	}
}

// TestCollectHwmonThermals_TempReadError covers hardware_linux.go:227.18,228.13 —
// the readFile error branch: a temp*_input file listed in the glob but not
// readable must be silently skipped (no thermal entry produced).
func TestCollectHwmonThermals_TempReadError(t *testing.T) {
	withFixtureSource(t, func(b *source.Bundle) {
		b.PutDir("/sys/class/hwmon", []string{"hwmon0"})
		b.PutFile("/sys/class/hwmon/hwmon0/name", []byte("k10temp\n"))
		b.PutGlob("/sys/class/hwmon/hwmon0/temp*_input", []string{"/sys/class/hwmon/hwmon0/temp1_input"})
		// temp1_input intentionally not seeded → readFile returns an error
	})
	info := &models.HardwareInfo{}
	collectHwmonThermals(info)
	if len(info.Thermals) != 0 {
		t.Errorf("Thermals = %v, want empty when temp file is unreadable", info.Thermals)
	}
}
