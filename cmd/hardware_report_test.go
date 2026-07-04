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

func TestPrintHardwareReportSATABadSectors(t *testing.T) {
	badSectors := captureStdout(t, func() {
		printHardwareReport(&models.HardwareInfo{Drives: []models.HardwareDrive{
			{Device: "sda", Type: "ata", SmartctlAvailable: true, SmartOK: true, ReallocatedSectors: 12},
		}}, output.ModePlain, 0)
	})
	if !strings.Contains(badSectors, "CRIT") {
		t.Errorf("12 reallocated sectors (>=10) should render CRIT, got:\n%s", badSectors)
	}
	if !strings.Contains(badSectors, "reallocated:12") {
		t.Errorf("the reallocated count should be shown, got:\n%s", badSectors)
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
}
