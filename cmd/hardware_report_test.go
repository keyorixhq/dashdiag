package cmd

import (
	"strings"
	"testing"

	"github.com/keyorixhq/dashdiag/internal/models"
	"github.com/keyorixhq/dashdiag/internal/output"
)

// Golden-output tests for hardware.go's printHardwareReport (0% covered) — a
// single flat renderer over a plain data struct, no live I/O. No
// t.Parallel() (corrupts captureStdout's shared os.Stdout swap).
// coreThermalLevel/driveThermalLevel already have full coverage as pure
// functions; these tests confirm the renderer actually wires them (and its
// own inline ECC/wear/bad-sector/NIC thresholds) into the printed output.

func TestPrintHardwareReportSystem(t *testing.T) {
	out := captureStdout(t, func() {
		printHardwareReport(&models.HardwareInfo{System: models.HardwareSystem{
			Vendor: "Dell Inc.", Model: "PowerEdge R740",
		}}, output.ModePlain, 0)
	})
	if !strings.Contains(out, "Dell Inc.") || !strings.Contains(out, "PowerEdge R740") {
		t.Errorf("system vendor/model should be shown, got:\n%s", out)
	}

	empty := captureStdout(t, func() { printHardwareReport(&models.HardwareInfo{}, output.ModePlain, 0) })
	if strings.Contains(empty, "System") {
		t.Errorf("an empty system vendor/model should not print a System section, got:\n%s", empty)
	}
}

// TestPrintHardwareReportSanitizesControlChars guards against terminal-escape
// injection via hardware-vendor/DMI, sysfs, and driver-sourced strings —
// System.Vendor/Model (DMI), drive Device/Model (sysfs/smartctl), thermal
// Label/Sensor (hwmon), and NIC Driver/MAC/Name (sysfs/ethtool) — all
// attacker-influenceable by hardware/firmware the operator doesn't fully
// trust (a hostile USB device, a crafted VM's virtual DMI/NIC identity).
func TestPrintHardwareReportSanitizesControlChars(t *testing.T) {
	const esc = "\x1b[2J"
	out := captureStdout(t, func() {
		printHardwareReport(&models.HardwareInfo{
			System: models.HardwareSystem{Vendor: "Dell Inc." + esc, Model: "PowerEdge" + esc},
			Drives: []models.HardwareDrive{
				{Device: "sda" + esc, Model: "Samsung" + esc, SmartctlAvailable: true, SmartOK: true},
			},
			Thermals: []models.HardwareThermal{{Label: "Package" + esc, Sensor: "coretemp" + esc, TempC: 50}},
			NICs:     []models.HardwareNIC{{Name: "eth0" + esc, State: "up", Driver: "ixgbe" + esc, MAC: "00:11:22" + esc}},
		}, output.ModePlain, 0)
	})
	if strings.Contains(out, esc) {
		t.Errorf("printHardwareReport must strip terminal escape sequences, got:\n%q", out)
	}
}

func TestPrintHardwareReportCPU(t *testing.T) {
	full := captureStdout(t, func() {
		printHardwareReport(&models.HardwareInfo{CPU: models.HardwareCPU{
			Model: "AMD EPYC 7402", Cores: 24, Threads: 48, FreqMHz: 2800, MaxFreqMHz: 3350,
		}}, output.ModePlain, 0)
	})
	for _, want := range []string{"AMD EPYC 7402", "24 cores / 48 threads", "2800 MHz (max 3350 MHz)"} {
		if !strings.Contains(full, want) {
			t.Errorf("CPU section missing %q, got:\n%s", want, full)
		}
	}

	// No model name (unknown fallback) and threads with no core count (the
	// "just threads" branch), no frequency at all.
	threadsOnly := captureStdout(t, func() {
		printHardwareReport(&models.HardwareInfo{CPU: models.HardwareCPU{Threads: 8}}, output.ModePlain, 0)
	})
	if !strings.Contains(threadsOnly, "unknown") {
		t.Errorf("an empty CPU model should render 'unknown', got:\n%s", threadsOnly)
	}
	if !strings.Contains(threadsOnly, "8 threads") {
		t.Errorf("threads with no core count should still be shown, got:\n%s", threadsOnly)
	}

	empty := captureStdout(t, func() { printHardwareReport(&models.HardwareInfo{}, output.ModePlain, 0) })
	if strings.Contains(empty, "CPU") {
		t.Errorf("an empty CPU model/threads should not print a CPU section, got:\n%s", empty)
	}
}

func TestPrintHardwareReportMemoryECC(t *testing.T) {
	noEDAC := captureStdout(t, func() {
		printHardwareReport(&models.HardwareInfo{Memory: models.HardwareMemory{EDACAvailable: false}}, output.ModePlain, 0)
	})
	if !strings.Contains(noEDAC, "EDAC not available") {
		t.Errorf("no EDAC should say unavailable, got:\n%s", noEDAC)
	}

	uncorrected := captureStdout(t, func() {
		printHardwareReport(&models.HardwareInfo{Memory: models.HardwareMemory{EDACAvailable: true, UncorrectedErrors: 1}}, output.ModePlain, 0)
	})
	if !strings.Contains(uncorrected, "CRIT") {
		t.Errorf("any uncorrected ECC error should render CRIT, got:\n%s", uncorrected)
	}

	corrected := captureStdout(t, func() {
		printHardwareReport(&models.HardwareInfo{Memory: models.HardwareMemory{EDACAvailable: true, CorrectedErrors: 150}}, output.ModePlain, 0)
	})
	if !strings.Contains(corrected, "WARN") {
		t.Errorf("150 corrected ECC errors (>100) should render WARN, got:\n%s", corrected)
	}
}

func TestPrintHardwareReportMemorySlots(t *testing.T) {
	out := captureStdout(t, func() {
		printHardwareReport(&models.HardwareInfo{Memory: models.HardwareMemory{
			TotalGB: 64,
			Slots:   []models.MemorySlot{{Locator: "DIMM_A1", SizeGB: 32, Type: "DDR5", SpeedMT: 4800}},
		}}, output.ModePlain, 0)
	})
	if !strings.Contains(out, "64 GB total") {
		t.Errorf("total RAM should be shown, got:\n%s", out)
	}
	if !strings.Contains(out, "DIMM_A1 — 32 GB DDR5 @ 4800 MT/s") {
		t.Errorf("a RAM slot should be shown, got:\n%s", out)
	}
}

func TestPrintHardwareReportNoDrives(t *testing.T) {
	out := captureStdout(t, func() { printHardwareReport(&models.HardwareInfo{}, output.ModePlain, 0) })
	if !strings.Contains(out, "no drives detected") {
		t.Errorf("no drives should say so, got:\n%s", out)
	}
}

func TestPrintHardwareReportDriveSmart(t *testing.T) {
	unavailable := captureStdout(t, func() {
		printHardwareReport(&models.HardwareInfo{Drives: []models.HardwareDrive{
			{Device: "sda", SmartctlAvailable: false, Error: "smartctl not installed"},
		}}, output.ModePlain, 0)
	})
	if !strings.Contains(unavailable, "smartctl not installed") {
		t.Errorf("unavailable smartctl should surface the error, got:\n%s", unavailable)
	}

	failed := captureStdout(t, func() {
		printHardwareReport(&models.HardwareInfo{Drives: []models.HardwareDrive{
			{Device: "sda", SmartctlAvailable: true, SmartOK: false},
		}}, output.ModePlain, 0)
	})
	if !strings.Contains(failed, "FAILED") {
		t.Errorf("SmartOK=false should render FAILED, got:\n%s", failed)
	}
}

func TestPrintHardwareReportDriveIdentityAndError(t *testing.T) {
	withModel := captureStdout(t, func() {
		printHardwareReport(&models.HardwareInfo{Drives: []models.HardwareDrive{
			{Device: "nvme0n1", Model: "Samsung 980 PRO", SmartctlAvailable: true, SmartOK: true},
		}}, output.ModePlain, 0)
	})
	if !strings.Contains(withModel, "nvme0n1 — Samsung 980 PRO") {
		t.Errorf("a known drive model should be shown alongside the device, got:\n%s", withModel)
	}

	// smartctl ran but the read itself failed (permission denied) — distinct
	// from SmartctlAvailable:false ("tool missing"), this is the "tool present,
	// read failed" branch.
	readFailed := captureStdout(t, func() {
		printHardwareReport(&models.HardwareInfo{Drives: []models.HardwareDrive{
			{Device: "sda", SmartctlAvailable: true, Error: "permission denied — run as root"},
		}}, output.ModePlain, 0)
	})
	if !strings.Contains(readFailed, "permission denied") {
		t.Errorf("a failed SMART read should surface its error, got:\n%s", readFailed)
	}
}

func TestPrintHardwareReportDrivePowerOn(t *testing.T) {
	out := captureStdout(t, func() {
		printHardwareReport(&models.HardwareInfo{Drives: []models.HardwareDrive{
			{Device: "sda", SmartctlAvailable: true, SmartOK: true, PowerOnH: 240},
		}}, output.ModePlain, 0)
	})
	if !strings.Contains(out, "240 h (10 days)") {
		t.Errorf("power-on hours should be shown with the days conversion, got:\n%s", out)
	}
}

func TestPrintHardwareReportDriveTemp(t *testing.T) {
	implausible := captureStdout(t, func() {
		printHardwareReport(&models.HardwareInfo{Drives: []models.HardwareDrive{
			{Device: "nvme0n1", Type: "nvme", SmartctlAvailable: true, SmartOK: true, TempC: 1000},
		}}, output.ModePlain, 0)
	})
	if !strings.Contains(implausible, "rejected") {
		t.Errorf("an implausible drive temp must be rejected, not rendered as a real reading, got:\n%s", implausible)
	}

	nvmeHot := captureStdout(t, func() {
		printHardwareReport(&models.HardwareInfo{Drives: []models.HardwareDrive{
			{Device: "nvme0n1", Type: "nvme", SmartctlAvailable: true, SmartOK: true, TempC: 85},
		}}, output.ModePlain, 0)
	})
	if !strings.Contains(nvmeHot, "CRIT") {
		t.Errorf("an 85C NVMe drive should render CRIT, got:\n%s", nvmeHot)
	}
}

func TestPrintHardwareReportDriveWear(t *testing.T) {
	worn := captureStdout(t, func() {
		printHardwareReport(&models.HardwareInfo{Drives: []models.HardwareDrive{
			{Device: "nvme0n1", SmartctlAvailable: true, SmartOK: true, WearPct: 96},
		}}, output.ModePlain, 0)
	})
	if !strings.Contains(worn, "CRIT") {
		t.Errorf("96%% wear should render CRIT, got:\n%s", worn)
	}
}

func TestPrintHardwareReportDriveWearWarn(t *testing.T) {
	out := captureStdout(t, func() {
		printHardwareReport(&models.HardwareInfo{Drives: []models.HardwareDrive{
			{Device: "nvme0n1", SmartctlAvailable: true, SmartOK: true, WearPct: 85},
		}}, output.ModePlain, 0)
	})
	if !strings.Contains(out, "WARN") {
		t.Errorf("85%% wear (>=80, <95) should render WARN, got:\n%s", out)
	}
	if strings.Contains(out, "CRIT") {
		t.Errorf("85%% wear must not render CRIT, got:\n%s", out)
	}
}

func TestPrintHardwareReportSATABadSectors(t *testing.T) {
	badSectors := captureStdout(t, func() {
		printHardwareReport(&models.HardwareInfo{Drives: []models.HardwareDrive{
			{Device: "sda", Type: "ata", SmartctlAvailable: true, SmartOK: true, BadSectorsRead: true, ReallocatedSectors: 12},
		}}, output.ModePlain, 0)
	})
	if !strings.Contains(badSectors, "CRIT") {
		t.Errorf("12 reallocated sectors (>=10) should render CRIT, got:\n%s", badSectors)
	}
	if !strings.Contains(badSectors, "reallocated:12") {
		t.Errorf("the reallocated count should be shown, got:\n%s", badSectors)
	}
}

// TestPrintHardwareReportSATABadSectorsUnread is a regression guard for
// cmd-06-02: a SAS drive (or any drive whose smartctl output lacks
// ata_smart_attributes) never populates Reallocated/Pending/Uncorrectable —
// they stay zero because nothing was measured, not because the drive is
// clean. Without BadSectorsRead set, the section must disclose "could not
// verify" instead of a green "Bad sectors: OK none".
func TestPrintHardwareReportSATABadSectorsUnread(t *testing.T) {
	out := captureStdout(t, func() {
		printHardwareReport(&models.HardwareInfo{Drives: []models.HardwareDrive{
			{Device: "sda", Type: "sas", SmartctlAvailable: true, SmartOK: true},
		}}, output.ModePlain, 0)
	})
	if !strings.Contains(out, "could not verify") {
		t.Errorf("a SAS drive with no ATA attribute data must disclose it could not verify bad sectors, got:\n%s", out)
	}
}

func TestPrintHardwareReportNVMeErrors(t *testing.T) {
	mediaErrs := captureStdout(t, func() {
		printHardwareReport(&models.HardwareInfo{Drives: []models.HardwareDrive{
			{Device: "nvme0n1", Type: "nvme", SmartctlAvailable: true, SmartOK: true, MediaErrors: 15},
		}}, output.ModePlain, 0)
	})
	if !strings.Contains(mediaErrs, "CRIT") {
		t.Errorf("15 NVMe media errors (>=10) should render CRIT, got:\n%s", mediaErrs)
	}
}

func TestPrintHardwareReportNVMeErrorsWarn(t *testing.T) {
	out := captureStdout(t, func() {
		printHardwareReport(&models.HardwareInfo{Drives: []models.HardwareDrive{
			{Device: "nvme0n1", Type: "nvme", SmartctlAvailable: true, SmartOK: true, MediaErrors: 3},
		}}, output.ModePlain, 0)
	})
	if !strings.Contains(out, "WARN") {
		t.Errorf("3 NVMe media errors (>0, <10) should render WARN, got:\n%s", out)
	}
	if strings.Contains(out, "CRIT") {
		t.Errorf("3 media errors must not render CRIT, got:\n%s", out)
	}
}

func TestPrintHardwareReportCPUThermals(t *testing.T) {
	// A 0-Kelvin sentinel (or other implausible reading) must not render a
	// confident icon — common on virtual/cloud hwmon.
	notReported := captureStdout(t, func() {
		printHardwareReport(&models.HardwareInfo{Thermals: []models.HardwareThermal{{Label: "Package", TempC: -273}}}, output.ModePlain, 0)
	})
	if !strings.Contains(notReported, "not reported") {
		t.Errorf("an implausible CPU thermal reading must say not reported, got:\n%s", notReported)
	}

	throttling := captureStdout(t, func() {
		printHardwareReport(&models.HardwareInfo{Thermals: []models.HardwareThermal{{Label: "Package", TempC: 98}}}, output.ModePlain, 0)
	})
	if !strings.Contains(throttling, "CRIT") || !strings.Contains(throttling, "throttling") {
		t.Errorf("a 98C core should render CRIT/throttling, got:\n%s", throttling)
	}
}

func TestPrintHardwareReportNICs(t *testing.T) {
	down := captureStdout(t, func() {
		printHardwareReport(&models.HardwareInfo{NICs: []models.HardwareNIC{{Name: "eth0", State: "down"}}}, output.ModePlain, 0)
	})
	if !strings.Contains(down, "WARN") {
		t.Errorf("a down NIC should render WARN, got:\n%s", down)
	}

	errs := captureStdout(t, func() {
		printHardwareReport(&models.HardwareInfo{NICs: []models.HardwareNIC{{Name: "eth0", State: "up", RxErrors: 5}}}, output.ModePlain, 0)
	})
	if !strings.Contains(errs, "rx_errors:5") {
		t.Errorf("NIC rx errors should be shown, got:\n%s", errs)
	}

	speedAndDriver := captureStdout(t, func() {
		printHardwareReport(&models.HardwareInfo{NICs: []models.HardwareNIC{
			{Name: "eth0", State: "up", SpeedMbps: 10000, Driver: "ixgbe"},
		}}, output.ModePlain, 0)
	})
	if !strings.Contains(speedAndDriver, "@ 10000 Mbps") || !strings.Contains(speedAndDriver, "[ixgbe]") {
		t.Errorf("NIC speed and driver should be shown, got:\n%s", speedAndDriver)
	}
}
