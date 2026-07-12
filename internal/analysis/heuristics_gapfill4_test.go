package analysis

import (
	"strings"
	"testing"

	"github.com/keyorixhq/dashdiag/internal/models"
)

// Characterization tests for small pure classification helpers in
// heuristics_postboot.go, heuristics_maintenance.go, heuristics_system.go,
// heuristics_resources.go, and heuristics_vmware.go.

func TestPostBootUnmeasurable(t *testing.T) {
	t.Parallel()
	tests := []struct {
		reason  string
		wantMsg string
	}{
		{"no_persistent_journal", "journald is volatile"},
		{"journal_unreadable", "not readable as this user"},
		{"non_systemd_no_wtmp", "no cross-boot record to read"},
		{"some_other_unknown_reason", "could not read any cross-boot source"},
		{"", "could not read any cross-boot source"},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.reason, func(t *testing.T) {
			t.Parallel()
			got := postBootUnmeasurable(models.PostBootInfo{Reason: tt.reason})
			if got.Level != "INFO" {
				t.Errorf("level = %q, want INFO", got.Level)
			}
			if !strings.Contains(got.Message, tt.wantMsg) {
				t.Errorf("message = %q, want substring %q", got.Message, tt.wantMsg)
			}
		})
	}
}

func TestKernelRetentionHints(t *testing.T) {
	t.Parallel()
	tests := []struct {
		pm       string
		wantFrom string
	}{
		{"zypper", "purge-kernels"},
		{"dnf", "dnf remove --oldinstallonly"},
		{"apt", "apt autoremove --purge"},
		{"unknown-pm", "apt autoremove --purge"}, // default
		{"", "apt autoremove --purge"},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.pm, func(t *testing.T) {
			t.Parallel()
			hints := kernelRetentionHints(tt.pm)
			found := false
			for _, h := range hints {
				if strings.Contains(h, tt.wantFrom) {
					found = true
				}
			}
			if !found {
				t.Errorf("kernelRetentionHints(%q) = %v, want a hint containing %q", tt.pm, hints, tt.wantFrom)
			}
		})
	}
}

func TestLivePatchInspectHint(t *testing.T) {
	t.Parallel()
	tests := []struct {
		tool string
		want string
	}{
		{"klp", "to inspect: klp -v patches"},
		{"kpatch", "to inspect: kpatch list"},
		{"unknown-tool", "to inspect: dmesg | grep -i livepatch"},
		{"", "to inspect: dmesg | grep -i livepatch"},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.tool, func(t *testing.T) {
			t.Parallel()
			if got := livePatchInspectHint(tt.tool); got != tt.want {
				t.Errorf("livePatchInspectHint(%q) = %q, want %q", tt.tool, got, tt.want)
			}
		})
	}
}

func TestSlowBootFix(t *testing.T) {
	t.Parallel()
	// A known unit returns a specific, non-empty hint set.
	got := slowBootFix("gpu-manager.service")
	if len(got) == 0 {
		t.Fatal("gpu-manager.service must return hints")
	}
	found := false
	for _, h := range got {
		if strings.Contains(h, "gpu-manager") {
			found = true
		}
	}
	if !found {
		t.Errorf("gpu-manager.service hints must mention gpu-manager, got %v", got)
	}

	got2 := slowBootFix("NetworkManager-wait-online.service")
	if len(got2) == 0 {
		t.Fatal("NetworkManager-wait-online.service must return hints")
	}

	// An unknown unit must not panic and returns some default (nil or a generic hint).
	gotUnknown := slowBootFix("totally-unknown-unit.service")
	_ = gotUnknown // just confirming no panic; content is whatever the default case is
}

func TestHealthDeepLoadCorroborates(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name string
		d    models.HealthDeepInfo
		want bool
	}{
		{"zero NumCPU is false", models.HealthDeepInfo{NumCPU: 0, LoadAvg1: 10}, false},
		{"negative NumCPU is false", models.HealthDeepInfo{NumCPU: -1, LoadAvg1: 10}, false},
		{"below floor", models.HealthDeepInfo{NumCPU: 4, LoadAvg1: 2.7}, false}, // 67.5%
		{"at floor", models.HealthDeepInfo{NumCPU: 4, LoadAvg1: 2.8}, true},     // 70%
		{"above floor", models.HealthDeepInfo{NumCPU: 4, LoadAvg1: 4.0}, true},  // 100%
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := healthDeepLoadCorroborates(tt.d); got != tt.want {
				t.Errorf("healthDeepLoadCorroborates(%+v) = %v, want %v", tt.d, got, tt.want)
			}
		})
	}
}

func TestVmwareCPULimitBinding(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name        string
		v           models.VMwareInfo
		wantBinding bool
		wantKnown   bool
	}{
		{
			name:        "implausibly low HostMHzPerCPU",
			v:           models.VMwareInfo{HostMHzPerCPU: 100, NumVCPU: 4, CPULimitMHz: 1000},
			wantBinding: false, wantKnown: false,
		},
		{
			name:        "implausibly high HostMHzPerCPU",
			v:           models.VMwareInfo{HostMHzPerCPU: 20000, NumVCPU: 4, CPULimitMHz: 1000},
			wantBinding: false, wantKnown: false,
		},
		{
			name:        "zero capacity (NumVCPU zero)",
			v:           models.VMwareInfo{HostMHzPerCPU: 2400, NumVCPU: 0, CPULimitMHz: 1000},
			wantBinding: false, wantKnown: false,
		},
		{
			name:        "limit binds below 98pct of capacity",
			v:           models.VMwareInfo{HostMHzPerCPU: 2400, NumVCPU: 4, CPULimitMHz: 4000}, // capacity 9600, 98%=9408
			wantBinding: true, wantKnown: true,
		},
		{
			name:        "limit at/above capacity means not binding",
			v:           models.VMwareInfo{HostMHzPerCPU: 2400, NumVCPU: 4, CPULimitMHz: 9600},
			wantBinding: false, wantKnown: true,
		},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			binding, known := vmwareCPULimitBinding(tt.v)
			if binding != tt.wantBinding || known != tt.wantKnown {
				t.Errorf("vmwareCPULimitBinding(%+v) = (%v,%v), want (%v,%v)", tt.v, binding, known, tt.wantBinding, tt.wantKnown)
			}
		})
	}
}
