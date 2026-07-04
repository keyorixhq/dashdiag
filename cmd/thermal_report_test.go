package cmd

import (
	"strings"
	"testing"

	"github.com/keyorixhq/dashdiag/internal/models"
	"github.com/keyorixhq/dashdiag/internal/output"
)

// Golden-output tests for thermal.go's printThermalReport (0% covered) — a
// single flat renderer over a plain data struct. No t.Parallel() (corrupts
// captureStdout's shared os.Stdout swap).

func TestPrintThermalReportNoSensors(t *testing.T) {
	out := captureStdout(t, func() { printThermalReport(&models.ThermalInfo{}, output.ModePlain, 0) })
	if !strings.Contains(out, "not available") {
		t.Errorf("no thermal source should say not available, got:\n%s", out)
	}
}

// TestPrintThermalReportUnreadable guards against claiming healthy when a
// sensor was detected but no temperature could actually be read (Source set,
// CPUTempC stayed 0) — mirrors the health heuristic's CPUTempC==0 gate.
func TestPrintThermalReportUnreadable(t *testing.T) {
	out := captureStdout(t, func() { printThermalReport(&models.ThermalInfo{Source: "hwmon", CPUTempC: 0}, output.ModePlain, 0) })
	if strings.Contains(out, "Thermal healthy") {
		t.Errorf("an unreadable temperature must not read healthy, got:\n%s", out)
	}
	if !strings.Contains(out, "unreadable") {
		t.Errorf("an unreadable temperature should say so explicitly, got:\n%s", out)
	}
}

func TestPrintThermalReportThresholds(t *testing.T) {
	crit := captureStdout(t, func() {
		printThermalReport(&models.ThermalInfo{Source: "hwmon", CPUTempC: 98}, output.ModePlain, 0)
	})
	if !strings.Contains(crit, "critical") {
		t.Errorf("98C should render critical, got:\n%s", crit)
	}

	warn := captureStdout(t, func() {
		printThermalReport(&models.ThermalInfo{Source: "hwmon", CPUTempC: 88}, output.ModePlain, 0)
	})
	if !strings.Contains(warn, "elevated") {
		t.Errorf("88C should render elevated, got:\n%s", warn)
	}

	healthy := captureStdout(t, func() {
		printThermalReport(&models.ThermalInfo{Source: "hwmon", CPUTempC: 55,
			CoreTemps: map[string]float64{"core0": 55, "core1": 96}}, output.ModePlain, 0)
	})
	if !strings.Contains(healthy, "core1") {
		t.Errorf("per-core sensor readings should be listed, got:\n%s", healthy)
	}
	if !strings.Contains(healthy, "CRIT") {
		t.Errorf("a 96C core sensor should render CRIT even if the primary CPU temp is fine, got:\n%s", healthy)
	}
}
