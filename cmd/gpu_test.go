package cmd

import (
	"strings"
	"testing"

	"github.com/keyorixhq/dashdiag/internal/models"
	"github.com/keyorixhq/dashdiag/internal/output"
)

func TestGPUDeviceHasMetrics(t *testing.T) {
	// An older Intel iGPU with no hwmon: detected (name/vendor/driver) but every
	// metric is zero — no health was actually read.
	if gpuDeviceHasMetrics(models.GPUDevice{Name: "Intel GPU (0116)", Vendor: "intel", DRMDriver: "i915"}) {
		t.Error("an all-zero Intel iGPU device must report no metrics")
	}
	if !gpuDeviceHasMetrics(models.GPUDevice{TempC: 45}) {
		t.Error("a device with a real temperature has metrics")
	}
	if !gpuDeviceHasMetrics(models.GPUDevice{MemTotalMB: 8192}) {
		t.Error("a device with VRAM has metrics")
	}
	if !gpuDeviceHasMetrics(models.GPUDevice{PowerDrawW: 12}) {
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
}
