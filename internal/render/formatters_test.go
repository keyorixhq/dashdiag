package render

import (
	"strings"
	"testing"

	"github.com/keyorixhq/dashdiag/internal/models"
)

// ── formatMBps ───────────────────────────────────────────────────────────────

func TestFormatMBps(t *testing.T) {
	cases := []struct {
		in   float64
		want string
	}{
		{2048, "2.0 GB"},
		{1536, "1.5 GB"},
		// Quirk pinned: the threshold is 1000 (decimal) but the divisor is 1024
		// (binary), so 1000–1023 MB display as "1.0 GB". Locking current behavior.
		{1000, "1.0 GB"},
		{999, "999.0 MB"},
		{1, "1.0 MB"},
		{0.5, "512 KB"},
		{0, "0 KB"},
	}
	for _, c := range cases {
		if got := formatMBps(c.in); got != c.want {
			t.Errorf("formatMBps(%v) = %q, want %q", c.in, got, c.want)
		}
	}
}

// ── pluralY ──────────────────────────────────────────────────────────────────

func TestPluralY(t *testing.T) {
	if got := pluralY(1); got != "y" {
		t.Errorf("pluralY(1) = %q, want y", got)
	}
	for _, n := range []int{0, 2, 5, -1} {
		if got := pluralY(n); got != "ies" {
			t.Errorf("pluralY(%d) = %q, want ies", n, got)
		}
	}
}

// ── inlineGPU (branches: 0 / 1 / 2 / 3+ devices) ─────────────────────────────

func TestInlineGPU(t *testing.T) {
	if got := inlineGPU(nil); got != "" {
		t.Errorf("nil = %q, want empty", got)
	}
	if got := inlineGPU(&models.GPUInfo{}); got != "" {
		t.Errorf("no devices = %q, want empty", got)
	}

	// Single GPU, all fields populated.
	one := &models.GPUInfo{Devices: []models.GPUDevice{
		{Name: "AMD RX", TempC: 75, UtilPct: 30, MemUsedMB: 2000, MemTotalMB: 8000},
	}}
	got := inlineGPU(one)
	for _, want := range []string{"AMD RX", "75°C", "30%", "2000/8000 MB VRAM"} {
		if !strings.Contains(got, want) {
			t.Errorf("single GPU %q missing %q", got, want)
		}
	}

	// Single GPU, only a name — zero-valued fields must be omitted.
	bare := inlineGPU(&models.GPUInfo{Devices: []models.GPUDevice{{Name: "iGPU"}}})
	if bare != "iGPU" {
		t.Errorf("bare GPU = %q, want just the name", bare)
	}

	// Two GPUs — both listed.
	two := inlineGPU(&models.GPUInfo{Devices: []models.GPUDevice{
		{Name: "A", TempC: 60}, {Name: "B", TempC: 70},
	}})
	if !strings.HasPrefix(two, "2 GPUs:") || !strings.Contains(two, "A") || !strings.Contains(two, "B") {
		t.Errorf("two GPUs = %q", two)
	}

	// 3+ GPUs — count + hottest device.
	three := inlineGPU(&models.GPUInfo{Devices: []models.GPUDevice{
		{Name: "A", TempC: 50}, {Name: "B", TempC: 90}, {Name: "C", TempC: 70},
	}})
	if !strings.HasPrefix(three, "3 GPUs") {
		t.Errorf("want '3 GPUs' prefix, got %q", three)
	}
	if !strings.Contains(three, "90°C") || !strings.Contains(three, "(B)") {
		t.Errorf("3+ GPUs must show hottest (B, 90°C), got %q", three)
	}
}

// ── ioInline (await-preferred, throughput fallback) ──────────────────────────

func TestIOInline(t *testing.T) {
	if got := ioInline(nil); got != "" {
		t.Errorf("nil devices = %q, want empty", got)
	}

	// Single device with await latency.
	if got := ioInline([]models.IODeviceInfo{{Name: "sda", AwaitMs: 18.6}}); got != "18.6 ms" {
		t.Errorf("single await = %q, want '18.6 ms'", got)
	}

	// Multiple devices — worst await wins and the device is named.
	got := ioInline([]models.IODeviceInfo{
		{Name: "sda", AwaitMs: 2.0}, {Name: "nvme0", AwaitMs: 25.4}, {Name: "sdb", AwaitMs: 5.0},
	})
	if got != "25.4 ms (nvme0)" {
		t.Errorf("multi await = %q, want '25.4 ms (nvme0)'", got)
	}

	// No await (macOS path) — falls back to summed throughput.
	tp := ioInline([]models.IODeviceInfo{
		{Name: "disk0", ReadMBps: 1.5, WriteMBps: 2.5},
	})
	if tp != "4.0 MB/s" {
		t.Errorf("throughput fallback = %q, want '4.0 MB/s'", tp)
	}

	// No await, no throughput → empty.
	if got := ioInline([]models.IODeviceInfo{{Name: "idle"}}); got != "" {
		t.Errorf("idle device = %q, want empty", got)
	}
}

// ── kernelSecInline (SELinux precedence over AppArmor) ───────────────────────

func TestKernelSecInline(t *testing.T) {
	cases := []struct {
		name string
		in   models.KernelSecurityInfo
		want string
	}{
		{"selinux", models.KernelSecurityInfo{SELinuxPresent: true, SELinuxMode: "enforcing"}, "SELinux enforcing"},
		{"apparmor", models.KernelSecurityInfo{AppArmorPresent: true, AppArmorMode: "complain"}, "AppArmor complain"},
		{"selinux wins", models.KernelSecurityInfo{
			SELinuxPresent: true, SELinuxMode: "permissive",
			AppArmorPresent: true, AppArmorMode: "enforce",
		}, "SELinux permissive"},
		{"present but no mode falls through", models.KernelSecurityInfo{
			SELinuxPresent: true, SELinuxMode: "",
			AppArmorPresent: true, AppArmorMode: "enforce",
		}, "AppArmor enforce"},
		{"neither", models.KernelSecurityInfo{}, ""},
	}
	for _, c := range cases {
		in := c.in
		if got := kernelSecInline(&in); got != c.want {
			t.Errorf("%s: kernelSecInline = %q, want %q", c.name, got, c.want)
		}
	}
}
