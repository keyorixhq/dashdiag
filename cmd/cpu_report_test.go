package cmd

import (
	"context"
	"strings"
	"testing"

	"github.com/keyorixhq/dashdiag/internal/models"
	"github.com/keyorixhq/dashdiag/internal/output"
)

// Golden-output tests for cpu.go's printCPUReport (0% covered, already
// nolint'd as a flat display renderer). It calls drilldown.TopProcessesByCPU
// internally — real but cheap (a single `ps` call on macOS, a 200ms two-sample
// delta on Linux) — so these tests do incur a little real I/O, same as the
// live command. No t.Parallel() (corrupts captureStdout's shared os.Stdout
// swap).

func TestPrintCPUReportIdentity(t *testing.T) {
	withModel := captureStdout(t, func() {
		printCPUReport(context.Background(), &models.CPUInfo{NumCPU: 8}, nil, nil,
			&models.HardwareInfo{CPU: models.HardwareCPU{Model: "AMD Ryzen 7", Cores: 8, Threads: 16}}, output.ModePlain, 0)
	})
	if !strings.Contains(withModel, "AMD Ryzen 7") || !strings.Contains(withModel, "hyperthreading") {
		t.Errorf("a known CPU model with SMT should show the model and hyperthreading note, got:\n%s", withModel)
	}

	noHW := captureStdout(t, func() {
		printCPUReport(context.Background(), &models.CPUInfo{NumCPU: 4}, nil, nil, nil, output.ModePlain, 0)
	})
	if !strings.Contains(noHW, "4 logical CPUs") {
		t.Errorf("no hardware info should fall back to the logical CPU count, got:\n%s", noHW)
	}
}

func TestPrintCPUReportLoadAndSteal(t *testing.T) {
	steal := captureStdout(t, func() {
		printCPUReport(context.Background(), &models.CPUInfo{NumCPU: 4, StealPct: 12}, nil, nil, nil, output.ModePlain, 0)
	})
	if !strings.Contains(steal, "hypervisor over-provisioned") {
		t.Errorf("a high steal percentage should hint at hypervisor over-provisioning, got:\n%s", steal)
	}

	iowait := captureStdout(t, func() {
		printCPUReport(context.Background(), &models.CPUInfo{NumCPU: 4, IOwaitPct: 15}, nil, nil, nil, output.ModePlain, 0)
	})
	if !strings.Contains(iowait, "IOWait:") {
		t.Errorf("a nonzero IOwaitPct should render the IOWait row, got:\n%s", iowait)
	}
}

func TestPrintCPUReportFrequency(t *testing.T) {
	// No cpufreq interface at all (common on VM/cloud guests) must not print
	// "0 MHz" as if it were a real reading.
	noCpufreq := captureStdout(t, func() {
		printCPUReport(context.Background(), &models.CPUInfo{NumCPU: 4}, &models.CPUFreqInfo{}, nil, nil, output.ModePlain, 0)
	})
	if !strings.Contains(noCpufreq, "unavailable") {
		t.Errorf("an all-zero CPUFreqInfo must say unavailable, not print 0 MHz, got:\n%s", noCpufreq)
	}
	if strings.Contains(noCpufreq, "0 MHz") {
		t.Errorf("must not render a fake 0 MHz reading, got:\n%s", noCpufreq)
	}

	throttled := captureStdout(t, func() {
		printCPUReport(context.Background(), &models.CPUInfo{NumCPU: 4, UsagePct: 50},
			&models.CPUFreqInfo{Governor: "performance", CurrentMHz: 1200, MaxMHz: 3000, ThrottledPct: 60}, nil, nil, output.ModePlain, 0)
	})
	if !strings.Contains(throttled, "CPU throttled under load") {
		t.Errorf("a throttled CPU under load should be flagged, got:\n%s", throttled)
	}
}

func TestPrintCPUReportThermalAndVerdict(t *testing.T) {
	hot := captureStdout(t, func() {
		printCPUReport(context.Background(), &models.CPUInfo{NumCPU: 4}, nil,
			&models.ThermalInfo{Available: true, CPUTempC: 97}, nil, output.ModePlain, 0)
	})
	if !strings.Contains(hot, "CRIT") {
		t.Errorf("a 97C CPU temp should render CRIT, got:\n%s", hot)
	}
	if !strings.Contains(hot, "concern(s) found") {
		t.Errorf("a 97C CPU temp should count as a concern in the summary, got:\n%s", hot)
	}

	healthy := captureStdout(t, func() {
		printCPUReport(context.Background(), &models.CPUInfo{NumCPU: 4, UsagePct: 10}, nil, nil, nil, output.ModePlain, 0)
	})
	if !strings.Contains(healthy, "CPU healthy") {
		t.Errorf("low usage with no thermal data should read healthy, got:\n%s", healthy)
	}
}

// TestPrintCPUReportThermal_SanitizesSensorLabel guards Finding:
// internal-collectors-32-07. The per-sensor CoreTemps map key comes verbatim
// from a temp*_label sysfs file, which this codebase's threat model treats
// as untrusted /sys content. Requires >1 CoreTemps entry to reach the
// per-sensor printing branch.
func TestPrintCPUReportThermal_SanitizesSensorLabel(t *testing.T) {
	out := captureStdout(t, func() {
		printCPUReport(context.Background(), &models.CPUInfo{NumCPU: 4}, nil,
			&models.ThermalInfo{Available: true, CPUTempC: 55,
				CoreTemps: map[string]float64{"\x1b[2Jevil": 60, "core1": 50}}, nil, output.ModePlain, 0)
	})
	if strings.ContainsRune(out, 0x1b) {
		t.Errorf("sensor label output contains a raw ESC byte, got:\n%q", out)
	}
	if !strings.Contains(out, "evil") {
		t.Errorf("printable text around the escape sequence must survive sanitization, got:\n%q", out)
	}
}

// TestRunCPU exercises runCPU's real (read-only) collector wiring in --plain
// and --json mode. Same real-I/O precedent as this file's other tests
// (drilldown.TopProcessesByCPU is a cheap real call the live command already
// pays for).
func TestRunCPU(t *testing.T) {
	plainCmd := newBareCloudCmd()
	plainCmd.SetContext(context.Background())
	_ = plainCmd.Flags().Set("plain", "true")
	plainOut := captureStdout(t, func() {
		if err := runCPU(plainCmd, nil); err != nil {
			t.Fatalf("runCPU (plain): %v", err)
		}
	})
	if !strings.Contains(plainOut, "Load") {
		t.Errorf("plain mode should render the Load section, got: %q", plainOut)
	}

	jsonCmd := newBareCloudCmd()
	jsonCmd.SetContext(context.Background())
	_ = jsonCmd.Flags().Set("json", "true")
	jsonOut := captureStdout(t, func() {
		if err := runCPU(jsonCmd, nil); err != nil {
			t.Fatalf("runCPU (json): %v", err)
		}
	})
	if !strings.Contains(jsonOut, `"cpu"`) {
		t.Errorf("json mode should emit a top-level cpu key, got: %q", jsonOut)
	}
}
