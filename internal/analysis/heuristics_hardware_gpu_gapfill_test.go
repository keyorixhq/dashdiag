package analysis

import (
	"testing"

	"github.com/keyorixhq/dashdiag/internal/models"
)

// Table-driven boundary tests for checkGPUDevice — the per-device GPU health
// checks (temperature, junction temperature, VRAM, DPM, sustained load). Called
// directly (bypassing checkGPU's isSteamOSHost() live-host gate) so these are
// hermetic: steamOS is passed in as a plain bool parameter.

func TestCheckGPUDevice_ThrottlingHintBySteamOS(t *testing.T) {
	t.Parallel()
	dev := models.GPUDevice{TempC: 50, Throttling: true, TDPCurrentW: 15, TDPLimitW: 15}

	notSteamOS := checkGPUDevice(dev, "GPU0", false)
	if !hasHintSubstr(notSteamOS, "WARN", "raise the power cap or improve cooling") {
		t.Errorf("non-SteamOS throttling hint must mention power cap/cooling, got %+v", notSteamOS)
	}

	steamOS := checkGPUDevice(dev, "GPU0", true)
	if !hasHintSubstr(steamOS, "WARN", "increase the TDP limit in Performance settings") {
		t.Errorf("SteamOS throttling hint must mention the Performance settings TDP limit, got %+v", steamOS)
	}
}

func TestCheckGPUDevice_JunctionTempBoundaries(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name      string
		tempC     int
		wantLevel string
		wantMsg   string
	}{
		{"emergency threshold", 100, "CRIT", "emergency thermal threshold"},
		{"approaching limit", 90, "WARN", "approaching thermal limit"},
		{"below warn floor", 50, "", ""},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			dev := models.GPUDevice{TempC: 50, TempJunctionC: tt.tempC}
			out := checkGPUDevice(dev, "GPU0", false)
			if tt.wantLevel == "" {
				if hasInsightMsg(out, "CRIT", "junction") || hasInsightMsg(out, "WARN", "junction") {
					t.Errorf("junction temp %d must not fire a junction insight, got %+v", tt.tempC, out)
				}
				return
			}
			if !hasInsightMsg(out, tt.wantLevel, tt.wantMsg) {
				t.Errorf("junction temp %d: want %s containing %q, got %+v", tt.tempC, tt.wantLevel, tt.wantMsg, out)
			}
		})
	}
}

func TestCheckGPUDevice_JunctionTempImplausible(t *testing.T) {
	t.Parallel()
	dev := models.GPUDevice{TempC: 50, TempJunctionC: 9000} // garbage sensor read
	out := checkGPUDevice(dev, "GPU0", false)
	if !hasInsightMsg(out, "WARN", "implausible junction temperature") {
		t.Errorf("implausible junction temp must WARN as unverified, not CRIT as overheating, got %+v", out)
	}
}

func TestCheckGPUDevice_VRAMPressureSkippedOnAPU(t *testing.T) {
	t.Parallel()
	dev := models.GPUDevice{TempC: 50, VRAMUsedPct: 95, IsAPU: true}
	out := checkGPUDevice(dev, "GPU0", false)
	if hasInsightMsg(out, "WARN", "VRAM at") {
		t.Errorf("an APU's shared-RAM VRAM must not fire the VRAM-pressure WARN, got %+v", out)
	}
}

func TestCheckGPUDevice_VRAMPressureDiscreteGPU(t *testing.T) {
	t.Parallel()
	dev := models.GPUDevice{TempC: 50, VRAMUsedPct: 95, IsAPU: false}
	out := checkGPUDevice(dev, "GPU0", false)
	if !hasInsightMsg(out, "WARN", "VRAM at 95%") {
		t.Errorf("a discrete GPU at 95%% VRAM must WARN, got %+v", out)
	}
}

func TestCheckGPUDevice_DPMStuckLowUnderLoad(t *testing.T) {
	t.Parallel()
	dev := models.GPUDevice{TempC: 50, PowerDPMLevel: "low", UtilPct: 60}
	out := checkGPUDevice(dev, "GPU0", false)
	if !hasInsightMsg(out, "WARN", "stuck in low-power DPM mode under load") {
		t.Errorf("DPM stuck low with genuine load (>=50%% util) must WARN, got %+v", out)
	}
}

func TestCheckGPUDevice_DPMLowWhileIdleIsNotAFault(t *testing.T) {
	t.Parallel()
	dev := models.GPUDevice{TempC: 50, PowerDPMLevel: "low", UtilPct: 5}
	out := checkGPUDevice(dev, "GPU0", false)
	if hasInsightMsg(out, "WARN", "stuck in low-power DPM") {
		t.Errorf("DPM low while idle (util < 50%%) must NOT WARN, got %+v", out)
	}
}

func TestCheckGPUDevice_MemUsedPctBoundaries(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name      string
		pct       float64
		wantLevel string
	}{
		{"below warn", 84, ""},
		{"at warn", 85, "WARN"},
		{"at crit", 95, "CRIT"},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			dev := models.GPUDevice{TempC: 50, MemUsedPct: tt.pct, MemUsedMB: 100, MemTotalMB: 100}
			out := checkGPUDevice(dev, "GPU0", false)
			got := hasInsightMsg(out, tt.wantLevel, "VRAM usage")
			if tt.wantLevel == "" {
				if hasInsightMsg(out, "WARN", "VRAM usage") || hasInsightMsg(out, "CRIT", "VRAM usage") {
					t.Errorf("MemUsedPct=%v must not fire a VRAM-usage insight, got %+v", tt.pct, out)
				}
				return
			}
			if !got {
				t.Errorf("MemUsedPct=%v must fire %s VRAM usage insight, got %+v", tt.pct, tt.wantLevel, out)
			}
		})
	}
}

func TestCheckGPUDevice_MemUsedPctSkippedOnAPU(t *testing.T) {
	t.Parallel()
	dev := models.GPUDevice{TempC: 50, MemUsedPct: 99, MemUsedMB: 100, MemTotalMB: 100, IsAPU: true}
	out := checkGPUDevice(dev, "GPU0", false)
	if hasInsightMsg(out, "WARN", "VRAM usage") || hasInsightMsg(out, "CRIT", "VRAM usage") {
		t.Errorf("APU must not fire the MB-based VRAM-usage check either, got %+v", out)
	}
}

func TestCheckGPUDevice_SustainedComputeLoad(t *testing.T) {
	t.Parallel()
	dev := models.GPUDevice{TempC: 50, UtilPct: 85, PowerDrawW: 150}
	out := checkGPUDevice(dev, "GPU0", false)
	if !hasInsightMsg(out, "INFO", "sustained compute load") {
		t.Errorf("high util+power must INFO sustained compute load, got %+v", out)
	}
}

func TestCheckGPUDevice_SustainedComputeLoadNotFiredBelowThreshold(t *testing.T) {
	t.Parallel()
	dev := models.GPUDevice{TempC: 50, UtilPct: 50, PowerDrawW: 50}
	out := checkGPUDevice(dev, "GPU0", false)
	if hasInsightMsg(out, "INFO", "sustained compute load") {
		t.Errorf("moderate util/power must not fire sustained-load INFO, got %+v", out)
	}
}

func TestCheckGPU_MultiDevicePrefix(t *testing.T) {
	t.Parallel()
	gpu := models.GPUInfo{Devices: []models.GPUDevice{
		{Index: 0, Name: "RTX 4090", TempC: 95},
		{Index: 1, Name: "RTX 4090", TempC: 50},
	}}
	out := checkGPU(gpu)
	if !hasInsightMsg(out, "CRIT", "GPU0 (RTX 4090)") {
		t.Errorf("multi-device GPU set must prefix insights with GPU<index> (<name>), got %+v", out)
	}
}

func TestCheckGPU_NvidiaNoDriver(t *testing.T) {
	t.Parallel()
	gpu := models.GPUInfo{Status: "nvidia-no-driver"}
	out := checkGPU(gpu)
	if !hasInsightMsg(out, "INFO", "install driver for GPU health monitoring") {
		t.Errorf("nvidia-no-driver status must INFO, got %+v", out)
	}
}
