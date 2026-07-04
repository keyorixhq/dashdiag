package cmd

import (
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
