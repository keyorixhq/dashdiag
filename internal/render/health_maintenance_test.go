package render

import (
	"testing"

	"github.com/keyorixhq/dashdiag/internal/models"
)

// Table-driven boundary tests for the RHEL/Oracle maintenance inline renderers
// (health_maintenance.go). Each covers: nil/wrong-type guard, unavailable, and
// every distinct branch inside the function.

func TestInlineKdump(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name string
		data any
		want string
	}{
		{"nil", nil, ""},
		{"wrong type", struct{ X int }{1}, ""},
		{"unavailable", models.KdumpInfo{Available: false}, ""},
		{"available but off", models.KdumpInfo{Available: true, Enabled: false}, "off"},
		{
			"armed", models.KdumpInfo{Available: true, Enabled: true, CrashLoaded: true, ReservedBytes: 512 * 1024 * 1024},
			"armed (512M reserved)",
		},
		{"enabled but not armed", models.KdumpInfo{Available: true, Enabled: true, CrashLoaded: false}, "NOT armed"},
		{
			"crash loaded but zero reserved", models.KdumpInfo{Available: true, Enabled: true, CrashLoaded: true, ReservedBytes: 0},
			"NOT armed",
		},
		{
			"pointer form", &models.KdumpInfo{Available: true, Enabled: true, CrashLoaded: true, ReservedBytes: 1024 * 1024 * 1024},
			"armed (1024M reserved)",
		},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := inlineKdump(tt.data); got != tt.want {
				t.Errorf("inlineKdump(%+v) = %q, want %q", tt.data, got, tt.want)
			}
		})
	}
}

func TestInlineTuned(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name string
		data any
		want string
	}{
		{"nil", nil, ""},
		{"wrong type", struct{ X int }{1}, ""},
		{"unavailable", models.TunedInfo{Available: false}, ""},
		{"inactive", models.TunedInfo{Available: true, Active: false}, "inactive"},
		{"active with profile", models.TunedInfo{Available: true, Active: true, Profile: "virtual-guest"}, "virtual-guest"},
		{"pointer form", &models.TunedInfo{Available: true, Active: true, Profile: "balanced"}, "balanced"},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := inlineTuned(tt.data); got != tt.want {
				t.Errorf("inlineTuned(%+v) = %q, want %q", tt.data, got, tt.want)
			}
		})
	}
}

func TestInlineKernelPatch(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name string
		data any
		want string
	}{
		{"nil", nil, ""},
		{"wrong type", struct{ X int }{1}, ""},
		{"unavailable", models.KernelPatchInfo{Available: false}, ""},
		{"reboot needed", models.KernelPatchInfo{Available: true, RebootNeeded: true}, "reboot pending"},
		{"no reboot needed", models.KernelPatchInfo{Available: true, RebootNeeded: false}, ""},
		{"pointer form reboot needed", &models.KernelPatchInfo{Available: true, RebootNeeded: true}, "reboot pending"},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := inlineKernelPatch(tt.data); got != tt.want {
				t.Errorf("inlineKernelPatch(%+v) = %q, want %q", tt.data, got, tt.want)
			}
		})
	}
}

func TestInlineKsplice(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name string
		data any
		want string
	}{
		{"nil", nil, ""},
		{"wrong type", struct{ X int }{1}, ""},
		{"unavailable", models.KspliceInfo{Available: false}, ""},
		{"pending updates", models.KspliceInfo{Available: true, PendingUpdates: 3}, "3 pending"},
		{"patched, no pending", models.KspliceInfo{Available: true, PendingUpdates: 0, Patched: true}, "live-patched"},
		{"neither pending nor patched", models.KspliceInfo{Available: true, PendingUpdates: 0, Patched: false}, ""},
		{"pointer form pending", &models.KspliceInfo{Available: true, PendingUpdates: 1}, "1 pending"},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := inlineKsplice(tt.data); got != tt.want {
				t.Errorf("inlineKsplice(%+v) = %q, want %q", tt.data, got, tt.want)
			}
		})
	}
}

func TestInlineServiceRestart(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name string
		data any
		want string
	}{
		{"nil", nil, ""},
		{"wrong type", struct{ X int }{1}, ""},
		{"unavailable", models.ServiceRestartInfo{Available: false}, ""},
		{"stale count", models.ServiceRestartInfo{Available: true, StaleCount: 2}, "2 need restart"},
		{"needs root, no stale", models.ServiceRestartInfo{Available: true, StaleCount: 0, NeedsRoot: true}, "partial (needs root)"},
		{"clean", models.ServiceRestartInfo{Available: true, StaleCount: 0, NeedsRoot: false}, ""},
		{"pointer form stale", &models.ServiceRestartInfo{Available: true, StaleCount: 5}, "5 need restart"},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := inlineServiceRestart(tt.data); got != tt.want {
				t.Errorf("inlineServiceRestart(%+v) = %q, want %q", tt.data, got, tt.want)
			}
		})
	}
}
