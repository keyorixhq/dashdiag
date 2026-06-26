package cmd

import (
	"strings"
	"testing"

	"github.com/keyorixhq/dashdiag/internal/analysis"
	"github.com/keyorixhq/dashdiag/internal/models"
	"github.com/keyorixhq/dashdiag/internal/output"
)

func TestGPUDeviceHasMetrics(t *testing.T) {
	// An older Intel iGPU with no hwmon: detected (name/vendor/driver) but every
	// metric is zero — no health was actually read.
	if analysis.GPUDeviceHasMetrics(models.GPUDevice{Name: "Intel GPU (0116)", Vendor: "intel", DRMDriver: "i915"}) {
		t.Error("an all-zero Intel iGPU device must report no metrics")
	}
	if !analysis.GPUDeviceHasMetrics(models.GPUDevice{TempC: 45}) {
		t.Error("a device with a real temperature has metrics")
	}
	if !analysis.GPUDeviceHasMetrics(models.GPUDevice{MemTotalMB: 8192}) {
		t.Error("a device with VRAM has metrics")
	}
	if !analysis.GPUDeviceHasMetrics(models.GPUDevice{PowerDrawW: 12}) {
		t.Error("a device with a power reading has metrics")
	}
}

func TestGPUSummaryLineMetricless(t *testing.T) {
	// The real MacBookAir4,2 case: one Intel HD 3000, no hwmon → all-zero metrics.
	// dsd gpu previously summarized this as "✅ GPU healthy. Checks passed" — a
	// false-OK, since nothing was measured.
	metricless := &models.GPUInfo{Devices: []models.GPUDevice{
		{Name: "Intel GPU (0116)", Vendor: "intel", DRMDriver: "i915"},
	}}
	got := gpuSummaryLine(metricless, "", output.ModePlain)
	if strings.Contains(got, "Checks passed") {
		t.Errorf("metricless GPU must NOT claim 'Checks passed', got: %q", got)
	}
	if !strings.Contains(got, "no health metrics") {
		t.Errorf("metricless GPU should report no metrics exposed, got: %q", got)
	}

	// A device WITH a real metric still summarizes as healthy.
	healthy := &models.GPUInfo{Devices: []models.GPUDevice{{Name: "RTX 3070", TempC: 50, MemTotalMB: 8192}}}
	if got := gpuSummaryLine(healthy, "", output.ModePlain); !strings.Contains(got, "Checks passed") {
		t.Errorf("a GPU with real metrics should report Checks passed, got: %q", got)
	}

	// MIXED: one readable GPU + one metricless. The readable one must NOT mask the
	// unmeasured device behind a plain "Checks passed" (the multi-GPU false-OK fix).
	mixed := &models.GPUInfo{Devices: []models.GPUDevice{
		{Name: "RTX 3070", TempC: 50, MemTotalMB: 8192},
		{Name: "Intel GPU (0116)", Vendor: "intel", DRMDriver: "i915"},
	}}
	got = gpuSummaryLine(mixed, "", output.ModePlain)
	if strings.Contains(got, "Checks passed") {
		t.Errorf("mixed readable+metricless must NOT claim 'Checks passed', got: %q", got)
	}
	if !strings.Contains(got, "no health metrics") {
		t.Errorf("mixed case should report the unmeasured GPU, got: %q", got)
	}
}

// TestGPUSummaryLineImplausibleTemp guards the §L/§Q raw-tool implausible-value
// class on the `dsd gpu` verdict path (gpuSummaryLine), so it cannot drift from
// checkGPUDevice (dsd health). A garbage hwmon read (thousands of °C) must NOT
// count as a thermal CRIT, but must still surface (WARN), never a false "healthy".
func TestGPUSummaryLineImplausibleTemp(t *testing.T) {
	garbage := &models.GPUInfo{Devices: []models.GPUDevice{{Name: "card0", TempC: 11758, MemTotalMB: 8192}}}
	got := gpuSummaryLine(garbage, "", output.ModePlain)
	if strings.Contains(got, "issue(s) found") {
		t.Errorf("implausible GPU temp must NOT be a CRIT, got: %q", got)
	}
	if strings.Contains(got, "Checks passed") {
		t.Errorf("implausible GPU temp must NOT read healthy (false-OK), got: %q", got)
	}
	if !strings.Contains(got, "elevated") {
		t.Errorf("implausible GPU temp should surface as a WARN/elevated, got: %q", got)
	}

	// A genuinely overheating GPU (in-range) must still CRIT — the gate must not
	// suppress a real thermal fault.
	overheat := &models.GPUInfo{Devices: []models.GPUDevice{{Name: "card0", TempC: 105, MemTotalMB: 8192}}}
	if got := gpuSummaryLine(overheat, "", output.ModePlain); !strings.Contains(got, "issue(s) found") {
		t.Errorf("a real 105°C overheat must still be a CRIT, got: %q", got)
	}
}
