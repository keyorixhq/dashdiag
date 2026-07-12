package analysis

import (
	"testing"

	"github.com/keyorixhq/dashdiag/internal/models"
)

// Fills branch gaps in checkHardware (drive-model prefix, the healthy-drive OK
// summary line) and checkIPMI (the default sensor-read-failed reason).

func TestCheckHardware_DriveModelPrefix(t *testing.T) {
	t.Parallel()
	h := models.HardwareInfo{Drives: []models.HardwareDrive{
		{Device: "/dev/sda", Model: "Samsung SSD 970", Type: "nvme", SmartctlAvailable: true, SmartRead: true, SmartOK: true},
	}}
	out := checkHardware(h)
	if !hasInsightMsg(out, "OK", "/dev/sda (Samsung SSD 970) — SMART OK") {
		t.Errorf("a drive with a Model must prefix the OK summary with '<device> (<model>)', got %+v", out)
	}
}

func TestCheckHardware_HealthyDriveOKSummary(t *testing.T) {
	t.Parallel()
	h := models.HardwareInfo{Drives: []models.HardwareDrive{
		{
			Device: "/dev/nvme0n1", Type: "nvme", SmartctlAvailable: true, SmartRead: true, SmartOK: true,
			TempC: 45, PowerOnH: 1000, WearPct: 3,
		},
	}}
	out := checkHardware(h)
	if !hasInsightMsg(out, "OK", "45°C") {
		t.Errorf("healthy-drive OK summary must include temperature when set, got %+v", out)
	}
	if !hasInsightMsg(out, "OK", "1000 h") {
		t.Errorf("healthy-drive OK summary must include power-on hours when set, got %+v", out)
	}
	if !hasInsightMsg(out, "OK", "3% worn") {
		t.Errorf("healthy-drive OK summary must include wear pct when set, got %+v", out)
	}
}

func TestCheckHardware_UnhealthyDriveNoOKSummary(t *testing.T) {
	t.Parallel()
	h := models.HardwareInfo{Drives: []models.HardwareDrive{
		{Device: "/dev/sda", Type: "sata", SmartctlAvailable: true, SmartRead: true, SmartOK: true, ReallocatedSectors: 20},
	}}
	out := checkHardware(h)
	if hasInsightMsg(out, "OK", "SMART OK") {
		t.Errorf("a drive with a CRIT-worthy finding must not also emit a healthy OK summary, got %+v", out)
	}
}

func TestCheckIPMI_ErrorDefaultReason(t *testing.T) {
	t.Parallel()
	ipmi := models.IPMIInfo{Status: "error", StatusReason: ""}
	out := checkIPMI(ipmi)
	if !hasInsightMsg(out, "WARN", "IPMI sensor read failed") {
		t.Errorf("empty StatusReason must fall back to the default sensor-read-failed message, got %+v", out)
	}
}

func TestCheckIPMI_ErrorCustomReason(t *testing.T) {
	t.Parallel()
	ipmi := models.IPMIInfo{Status: "error", StatusReason: "ipmitool: command not found"}
	out := checkIPMI(ipmi)
	if !hasInsightMsg(out, "WARN", "ipmitool: command not found") {
		t.Errorf("non-empty StatusReason must be used verbatim, got %+v", out)
	}
}
