package cmd

import (
	"context"
	"strings"
	"testing"

	"github.com/keyorixhq/dashdiag/internal/models"
	"github.com/keyorixhq/dashdiag/internal/output"
)

// Golden-output tests for gpu.go's report renderers (gpuSummaryLine already
// had coverage from an earlier round; this covers the section renderers that
// build up to it). Plain data structs, no live I/O. No t.Parallel() (corrupts
// captureStdout's shared os.Stdout swap).

func TestPrintGPUReportNoGPU(t *testing.T) {
	out := captureStdout(t, func() { printGPUReport(&models.GPUInfo{}, 0, output.ModePlain) })
	if !strings.Contains(out, "no GPU detected") {
		t.Errorf("no devices and no NoDriver entries should say no GPU detected, got:\n%s", out)
	}
}

func TestPrintGPUHeader(t *testing.T) {
	out := captureStdout(t, func() {
		printGPUHeader(models.GPUDevice{Name: "RX 6800", DRMDriver: "amdgpu", MesaVersion: "24.3.1"}, "", output.ModePlain)
	})
	if !strings.Contains(out, "amdgpu") || !strings.Contains(out, "Mesa 24.3.1") {
		t.Errorf("driver and Mesa version should both be shown, got:\n%s", out)
	}
}

// TestPrintGPUHeaderNvidia covers the NVIDIA-specific branches: an empty
// DRMDriver falls back to "nvidia", and a non-empty driverVersion is appended.
func TestPrintGPUHeaderNvidia(t *testing.T) {
	out := captureStdout(t, func() {
		printGPUHeader(models.GPUDevice{Name: "RTX 4090", Vendor: "nvidia"}, "550.120", output.ModePlain)
	})
	if !strings.Contains(out, "Driver: nvidia") {
		t.Errorf("an NVIDIA device with no DRMDriver should fall back to 'nvidia', got:\n%s", out)
	}
	if !strings.Contains(out, "550.120") {
		t.Errorf("a non-empty driverVersion should be shown for NVIDIA, got:\n%s", out)
	}
}

// TestPrintGPUHeaderNoExtras covers the empty-suffix branch: no driver, no
// version, no Mesa — just the bare device name.
func TestPrintGPUHeaderNoExtras(t *testing.T) {
	out := captureStdout(t, func() {
		printGPUHeader(models.GPUDevice{Name: "Bare GPU"}, "", output.ModePlain)
	})
	if !strings.Contains(out, "[Bare GPU]\n") {
		t.Errorf("no driver/version/Mesa info should print just the bracketed name, got:\n%s", out)
	}
}

func TestPrintGPUTemps(t *testing.T) {
	if out := captureStdout(t, func() { printGPUTemps(models.GPUDevice{}, output.ModePlain) }); out != "" {
		t.Errorf("a device with no temp readings should print nothing, got:\n%s", out)
	}

	// Intel-style single sensor (no junction/mem split).
	single := captureStdout(t, func() { printGPUTemps(models.GPUDevice{TempC: 60}, output.ModePlain) })
	if !strings.Contains(single, "60°C") {
		t.Errorf("a single-sensor device should show its temp, got:\n%s", single)
	}

	// AMD-style split with a junction temp near the thermal limit.
	split := captureStdout(t, func() {
		printGPUTemps(models.GPUDevice{TempC: 70, TempJunctionC: 92, TempMemC: 80}, output.ModePlain)
	})
	if !strings.Contains(split, "approaching thermal limit") {
		t.Errorf("a junction temp >=90C should note approaching the thermal limit, got:\n%s", split)
	}
}

func TestPrintGPUPerformance(t *testing.T) {
	if out := captureStdout(t, func() { printGPUPerformance(models.GPUDevice{}, output.ModePlain) }); out != "" {
		t.Errorf("a device with no performance data should print nothing, got:\n%s", out)
	}

	throttling := captureStdout(t, func() {
		printGPUPerformance(models.GPUDevice{TDPLimitW: 100, TDPCurrentW: 99, Throttling: true}, output.ModePlain)
	})
	if !strings.Contains(throttling, "throttling") {
		t.Errorf("a throttling device should be flagged, got:\n%s", throttling)
	}

	apu := captureStdout(t, func() {
		printGPUPerformance(models.GPUDevice{VRAMTotalGB: 1, VRAMUsedGB: 0.95, VRAMUsedPct: 95, IsAPU: true}, output.ModePlain)
	})
	if !strings.Contains(apu, "shared APU memory") {
		t.Errorf("an APU's VRAM line should note shared memory, got:\n%s", apu)
	}

	unreadable := captureStdout(t, func() { printGPUPerformance(models.GPUDevice{Unreadable: true}, output.ModePlain) })
	if !strings.Contains(unreadable, "fallen off the bus") {
		t.Errorf("an unreadable device should note it may have fallen off the bus, got:\n%s", unreadable)
	}
}

// TestPrintGPUPerformanceExtra exercises the branches TestPrintGPUPerformance
// above doesn't reach: clock/max, MemTotalMB (non-dedicated VRAM), high
// utilization, a low DPM level under load, and a running-process list.
func TestPrintGPUPerformanceExtra(t *testing.T) {
	out := captureStdout(t, func() {
		printGPUPerformance(models.GPUDevice{
			ClockMHz: 1500, ClockMaxMHz: 2000,
			MemTotalMB: 4096, MemUsedMB: 2048, MemUsedPct: 50,
			UtilPct:       97,
			PowerDPMLevel: "low",
			Processes:     []models.GPUProcess{{PID: 1234, MemUseMB: 512, Name: "compositor"}},
		}, output.ModePlain)
	})
	if !strings.Contains(out, "1500 / 2000 MHz") {
		t.Errorf("clock and max clock should both render, got:\n%s", out)
	}
	if !strings.Contains(out, "2048 / 4096 MB") {
		t.Errorf("non-dedicated VRAM (MemTotalMB) should render, got:\n%s", out)
	}
	if !strings.Contains(out, "Utilization: 97%") {
		t.Errorf("utilization should render, got:\n%s", out)
	}
	if !strings.Contains(out, "DPM level:   low") {
		t.Errorf("DPM level should render, got:\n%s", out)
	}
	if !strings.Contains(out, "compositor") {
		t.Errorf("a running GPU process should be listed, got:\n%s", out)
	}
}

func TestGPUHints(t *testing.T) {
	// An implausible junction reading must be surfaced as unverified, not a
	// scary emergency-threshold CRIT.
	implausible := gpuHints(&models.GPUInfo{Devices: []models.GPUDevice{{TempJunctionC: 50000}}}, false, output.ModePlain)
	joined := strings.Join(implausible, "\n")
	if !strings.Contains(joined, "implausible") {
		t.Errorf("an implausible junction temp should be flagged as such, got:\n%s", joined)
	}

	emergency := gpuHints(&models.GPUInfo{Devices: []models.GPUDevice{{TempJunctionC: 101}}}, false, output.ModePlain)
	joined = strings.Join(emergency, "\n")
	if !strings.Contains(joined, "emergency thermal threshold") {
		t.Errorf("a 101C junction temp should hit the emergency threshold hint, got:\n%s", joined)
	}

	// A Steam Deck (steamOS=true) gets device-specific throttling remediation.
	steamDeck := gpuHints(&models.GPUInfo{Devices: []models.GPUDevice{{Throttling: true, TDPLimitW: 15, TDPCurrentW: 15}}}, true, output.ModePlain)
	joined = strings.Join(steamDeck, "\n")
	if !strings.Contains(joined, "Steam Deck") {
		t.Errorf("throttling on SteamOS should give the Deck-specific hint, got:\n%s", joined)
	}

	// An APU's high VRAM usage must NOT hint memory pressure (shared RAM by design).
	apuNoHint := gpuHints(&models.GPUInfo{Devices: []models.GPUDevice{{VRAMUsedPct: 95, IsAPU: true}}}, false, output.ModePlain)
	if len(apuNoHint) != 0 {
		t.Errorf("an APU at 95%% VRAM must not hint memory pressure, got:\n%s", strings.Join(apuNoHint, "\n"))
	}

	// A discrete GPU's high VRAM usage DOES hint memory pressure.
	vramPressure := gpuHints(&models.GPUInfo{Devices: []models.GPUDevice{{VRAMUsedPct: 92, IsAPU: false}}}, false, output.ModePlain)
	joined = strings.Join(vramPressure, "\n")
	if !strings.Contains(joined, "high memory pressure") {
		t.Errorf("a non-APU at 92%% VRAM should hint memory pressure, got:\n%s", joined)
	}

	// A non-SteamOS host gets the generic throttling remediation, not the Deck one.
	nonDeck := gpuHints(&models.GPUInfo{Devices: []models.GPUDevice{{Throttling: true, TDPLimitW: 300, TDPCurrentW: 300}}}, false, output.ModePlain)
	joined = strings.Join(nonDeck, "\n")
	if !strings.Contains(joined, "Raise the power cap") {
		t.Errorf("throttling off SteamOS should give the generic hint, got:\n%s", joined)
	}
	if strings.Contains(joined, "Steam Deck") {
		t.Errorf("throttling off SteamOS must not mention Steam Deck, got:\n%s", joined)
	}

	// The 90-99C WARN band (below the 100C emergency threshold).
	warnBand := gpuHints(&models.GPUInfo{Devices: []models.GPUDevice{{TempJunctionC: 92}}}, false, output.ModePlain)
	joined = strings.Join(warnBand, "\n")
	if !strings.Contains(joined, "approaching 90") {
		t.Errorf("a 92C junction temp should hit the approaching-90C WARN hint, got:\n%s", joined)
	}

	// DPM stuck in low-power mode under load.
	dpmStuck := gpuHints(&models.GPUInfo{Devices: []models.GPUDevice{{PowerDPMLevel: "low", UtilPct: 75}}}, false, output.ModePlain)
	joined = strings.Join(dpmStuck, "\n")
	if !strings.Contains(joined, "stuck in low-power DPM mode") {
		t.Errorf("a GPU stuck in low DPM under load should hint so, got:\n%s", joined)
	}
}

func TestPrintGPUNoDriver(t *testing.T) {
	if out := captureStdout(t, func() { printGPUNoDriver(nil, output.ModePlain) }); out != "" {
		t.Errorf("no undriven GPUs should print nothing, got:\n%s", out)
	}

	nvidia := captureStdout(t, func() {
		printGPUNoDriver([]models.GPUDetected{{Name: "RTX 4090", Vendor: "nvidia"}}, output.ModePlain)
	})
	if !strings.Contains(nvidia, "akmod-nvidia") {
		t.Errorf("an undriven NVIDIA GPU should suggest the RPM Fusion package, got:\n%s", nvidia)
	}

	amd := captureStdout(t, func() {
		printGPUNoDriver([]models.GPUDetected{{Name: "RX 6800", Vendor: "amd"}}, output.ModePlain)
	})
	if !strings.Contains(amd, "modprobe amdgpu") {
		t.Errorf("an undriven AMD GPU should suggest modprobe amdgpu, got:\n%s", amd)
	}

	// nouveau bound (open-source driver active, proprietary metrics unavailable)
	// takes a different remediation branch than "no driver at all".
	nouveau := captureStdout(t, func() {
		printGPUNoDriver([]models.GPUDetected{{Name: "GeForce nouveau", Vendor: "nvidia", PCIAddr: "0000:01:00.0"}}, output.ModePlain)
	})
	if !strings.Contains(nouveau, "nouveau is bound") {
		t.Errorf("a nouveau-bound NVIDIA GPU should get the nouveau-specific hint, got:\n%s", nouveau)
	}
	if !strings.Contains(nouveau, "@ 0000:01:00.0") {
		t.Errorf("a device with a PCI address should show it, got:\n%s", nouveau)
	}
}

// TestPrintGPUDeviceDispatch exercises the Header/Temps/Performance dispatch
// (each is already covered directly above).
func TestPrintGPUDeviceDispatch(t *testing.T) {
	out := captureStdout(t, func() {
		printGPUDevice(models.GPUDevice{Name: "RX 6800", DRMDriver: "amdgpu", TempC: 60, TDPLimitW: 200, TDPCurrentW: 100}, "", output.ModePlain)
	})
	if !strings.Contains(out, "RX 6800") || !strings.Contains(out, "60°C") || !strings.Contains(out, "TDP") {
		t.Errorf("the device header, temps, and performance sections should all render, got:\n%s", out)
	}
}

// TestPrintGPUReportWithDevices exercises printGPUReport's full path (the
// top-level function was previously only covered via the no-GPU early
// return): device loop, hints section, and the summary line, for both a
// clean device and one with a hint-worthy condition (throttling).
func TestPrintGPUReportWithDevices(t *testing.T) {
	clean := captureStdout(t, func() {
		printGPUReport(&models.GPUInfo{Devices: []models.GPUDevice{
			{Name: "RTX 3070", TempC: 50, MemTotalMB: 8192},
		}}, 0, output.ModePlain)
	})
	if !strings.Contains(clean, "RTX 3070") {
		t.Errorf("the device should be rendered, got:\n%s", clean)
	}
	if !strings.Contains(clean, "Checks passed") {
		t.Errorf("a healthy device with no hints should read Checks passed, got:\n%s", clean)
	}

	throttling := captureStdout(t, func() {
		printGPUReport(&models.GPUInfo{Devices: []models.GPUDevice{
			{Name: "RX 6800", TempC: 60, TDPLimitW: 200, TDPCurrentW: 199, Throttling: true},
		}}, 0, output.ModePlain)
	})
	if !strings.Contains(throttling, "throttling") {
		t.Errorf("a throttling device should print the hint section, got:\n%s", throttling)
	}
	if !strings.Contains(throttling, "GPU elevated") {
		t.Errorf("a throttling device should summarize as elevated, got:\n%s", throttling)
	}

	undriven := captureStdout(t, func() {
		printGPUReport(&models.GPUInfo{NoDriver: []models.GPUDetected{{Name: "RX 6800", Vendor: "amd"}}}, 0, output.ModePlain)
	})
	if !strings.Contains(undriven, "modprobe amdgpu") {
		t.Errorf("an undriven-only report should render the no-driver section, got:\n%s", undriven)
	}
}

// TestRunGPU exercises runGPU's real (read-only) collector wiring in --plain
// and --json mode. Same real-I/O precedent as cpu_report_test.go.
func TestRunGPU(t *testing.T) {
	plainCmd := newBareCloudCmd()
	plainCmd.SetContext(context.Background())
	_ = plainCmd.Flags().Set("plain", "true")
	plainOut := captureStdout(t, func() {
		if err := runGPU(plainCmd, nil); err != nil {
			t.Fatalf("runGPU (plain): %v", err)
		}
	})
	if plainOut == "" {
		t.Error("runGPU (plain) produced no output")
	}

	jsonCmd := newBareCloudCmd()
	jsonCmd.SetContext(context.Background())
	_ = jsonCmd.Flags().Set("json", "true")
	jsonOut := captureStdout(t, func() {
		if err := runGPU(jsonCmd, nil); err != nil {
			t.Fatalf("runGPU (json): %v", err)
		}
	})
	if jsonOut == "" {
		t.Error("runGPU (json) produced no output")
	}
}
