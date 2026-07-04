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
