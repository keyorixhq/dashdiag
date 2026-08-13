package cmd

import (
	"context"
	"strings"
	"testing"
	"time"

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

	// A per-sensor reading in the 85-95 WARN band is a distinct icon branch
	// from both the OK (55) and CRIT (96) sensors above.
	sensorWarn := captureStdout(t, func() {
		printThermalReport(&models.ThermalInfo{Source: "hwmon", CPUTempC: 55,
			CoreTemps: map[string]float64{"core0": 88}}, output.ModePlain, 0)
	})
	if !strings.Contains(sensorWarn, "WARN") {
		t.Errorf("a per-sensor reading in the WARN band should render WARN, got:\n%s", sensorWarn)
	}
}

// TestPrintThermalReport_SanitizesSensorLabel guards Finding:
// internal-collectors-32-07. The sensor label comes verbatim from a
// temp*_label sysfs file, which this codebase's threat model treats as
// untrusted /sys content.
func TestPrintThermalReport_SanitizesSensorLabel(t *testing.T) {
	out := captureStdout(t, func() {
		printThermalReport(&models.ThermalInfo{Source: "hwmon", CPUTempC: 55,
			CoreTemps: map[string]float64{"\x1b[2Jevil": 60}}, output.ModePlain, 0)
	})
	if strings.ContainsRune(out, 0x1b) {
		t.Errorf("sensor label output contains a raw ESC byte, got:\n%q", out)
	}
	if !strings.Contains(out, "evil") {
		t.Errorf("printable text around the escape sequence must survive sanitization, got:\n%q", out)
	}
}

// TestRunThermal exercises runThermal's real (read-only) collector wiring in
// --plain and --json mode (non-watch). Same real-I/O precedent as
// cpu_report_test.go.
func TestRunThermal(t *testing.T) {
	plainCmd := newBareCloudCmd()
	plainCmd.SetContext(context.Background())
	_ = plainCmd.Flags().Set("plain", "true")
	plainOut := captureStdout(t, func() {
		if err := runThermal(plainCmd, nil); err != nil {
			t.Fatalf("runThermal (plain): %v", err)
		}
	})
	if plainOut == "" {
		t.Error("runThermal (plain) produced no output")
	}

	jsonCmd := newBareCloudCmd()
	jsonCmd.SetContext(context.Background())
	_ = jsonCmd.Flags().Set("json", "true")
	jsonOut := captureStdout(t, func() {
		if err := runThermal(jsonCmd, nil); err != nil {
			t.Fatalf("runThermal (json): %v", err)
		}
	})
	if !strings.Contains(jsonOut, "{") {
		t.Errorf("json mode should emit JSON, got: %q", jsonOut)
	}
}

// TestWatchThermal exercises watchThermal's one-shot run (real collector,
// same cost as TestRunThermal) plus its ctx.Done() exit path — an
// already-cancelled context makes the select loop return immediately after
// the first run instead of blocking on the ticker.
func TestWatchThermal(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	out := captureStdout(t, func() {
		if err := watchThermal(ctx, time.Millisecond, output.ModePlain); err != nil {
			t.Fatalf("watchThermal: %v", err)
		}
	})
	// A container/VM with no thermal source produces no ThermalInfo (nil result
	// data), which is the run() early-return branch — still valid coverage of
	// watchThermal's body, just not guaranteed to print a report line. Assert
	// only that it didn't panic/error, mirroring the honest-degradation pattern
	// used elsewhere in this package.
	_ = out
}
