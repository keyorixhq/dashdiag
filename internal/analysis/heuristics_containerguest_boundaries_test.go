package analysis

import (
	"testing"

	"github.com/keyorixhq/dashdiag/internal/models"
)

// Boundary/branch tests for checkContainerGuest's individual WARN/INFO findings
// and its small pure helpers — heuristics_containerguest_test.go already covers
// the cgroup-v1-measured behaviour; this file rounds out the per-condition
// WARN/INFO branches that weren't yet exercised (each toggled independently
// against an otherwise-clean baseline, matching the file's own doc comments).

func TestCheckContainerGuest_NoMemLimit(t *testing.T) {
	t.Parallel()
	v := models.ContainerGuestInfo{InContainer: true, CgroupV2: true, CPUQuotaCores: 1}
	out := checkContainerGuest(v)
	if !hasInsightMsg(out, "WARN", "no memory limit set") {
		t.Errorf("missing memory limit must WARN, got %+v", out)
	}
}

func TestCheckContainerGuest_RunAsRoot(t *testing.T) {
	t.Parallel()
	v := models.ContainerGuestInfo{InContainer: true, CgroupV2: true, MemLimitBytes: 256 << 20, CPUQuotaCores: 1, RunAsRoot: true}
	out := checkContainerGuest(v)
	if !hasInsightMsg(out, "WARN", "runs as root") {
		t.Errorf("RunAsRoot must WARN, got %+v", out)
	}
}

func TestCheckContainerGuest_NoCPULimit(t *testing.T) {
	t.Parallel()
	v := models.ContainerGuestInfo{InContainer: true, CgroupV2: true, MemLimitBytes: 256 << 20}
	out := checkContainerGuest(v)
	if !hasInsightMsg(out, "INFO", "no CPU limit set") {
		t.Errorf("missing CPU limit must INFO, got %+v", out)
	}
}

func TestCheckContainerGuest_WritableRootfs(t *testing.T) {
	t.Parallel()
	v := models.ContainerGuestInfo{InContainer: true, CgroupV2: true, MemLimitBytes: 256 << 20, CPUQuotaCores: 1, WritableRootfs: true}
	out := checkContainerGuest(v)
	if !hasInsightMsg(out, "INFO", "root filesystem is writable") {
		t.Errorf("writable rootfs must INFO, got %+v", out)
	}
}

func TestCheckContainerGuest_OOMKills(t *testing.T) {
	t.Parallel()
	v := models.ContainerGuestInfo{InContainer: true, CgroupV2: true, MemLimitBytes: 256 << 20, CPUQuotaCores: 1, OOMKills: 3}
	out := checkContainerGuest(v)
	if !hasInsightMsg(out, "WARN", "3 OOM-kill(s)") {
		t.Errorf("OOM-kills must WARN with count, got %+v", out)
	}
}

func TestCheckContainerGuest_MemNearLimit(t *testing.T) {
	t.Parallel()
	v := models.ContainerGuestInfo{
		InContainer: true, CgroupV2: true, CPUQuotaCores: 1,
		MemLimitBytes: 1000, MemCurrentBytes: 950, // 95%
	}
	out := checkContainerGuest(v)
	if !hasInsightMsg(out, "WARN", "memory at 95%") {
		t.Errorf("memory near limit must WARN with pct, got %+v", out)
	}
}

func TestContainerThrottleInsight_Boundaries(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name     string
		pct      float64
		wantWarn bool
	}{
		{"below threshold", containerThrottleWarnPct - 0.1, false},
		{"at threshold", containerThrottleWarnPct, true},
		{"above threshold", containerThrottleWarnPct + 10, true},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			v := models.ContainerGuestInfo{ThrottledPct: tt.pct, CPUQuotaCores: 2}
			out := containerThrottleInsight(v)
			got := hasInsightMsg(out, "WARN", "CPU throttled")
			if got != tt.wantWarn {
				t.Errorf("pct=%.1f: wantWarn=%v got=%v (%+v)", tt.pct, tt.wantWarn, got, out)
			}
		})
	}
}

func TestContainerThrottleInsight_NoQuotaLabel(t *testing.T) {
	t.Parallel()
	v := models.ContainerGuestInfo{ThrottledPct: 50, CPUQuotaCores: 0}
	out := containerThrottleInsight(v)
	if !hasInsightMsg(out, "WARN", "keeps hitting the CPU quota;") {
		t.Errorf("zero quota cores must use the generic 'the CPU quota' label, got %+v", out)
	}
}

func TestContainerMemPct(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name string
		v    models.ContainerGuestInfo
		want float64
	}{
		{"no limit", models.ContainerGuestInfo{MemLimitBytes: 0, MemCurrentBytes: 100}, 0},
		{"no current", models.ContainerGuestInfo{MemLimitBytes: 100, MemCurrentBytes: 0}, 0},
		{"half", models.ContainerGuestInfo{MemLimitBytes: 200, MemCurrentBytes: 100}, 50},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := containerMemPct(tt.v); got != tt.want {
				t.Errorf("containerMemPct(%+v) = %v, want %v", tt.v, got, tt.want)
			}
		})
	}
}

func TestContainerRuntimeLabel(t *testing.T) {
	t.Parallel()
	if got := containerRuntimeLabel(models.ContainerGuestInfo{}); got != "container" {
		t.Errorf("empty Runtime must fall back to 'container', got %q", got)
	}
	if got := containerRuntimeLabel(models.ContainerGuestInfo{Runtime: "docker"}); got != "docker" {
		t.Errorf("non-empty Runtime must be returned as-is, got %q", got)
	}
}

func TestContainerUnderlaySuffix(t *testing.T) {
	t.Parallel()
	if got := containerUnderlaySuffix(models.ContainerGuestInfo{}); got != "" {
		t.Errorf("empty UnderlyingVM must produce empty suffix, got %q", got)
	}
	if got := containerUnderlaySuffix(models.ContainerGuestInfo{UnderlyingVM: "VMware"}); got != " (on a VMware VM)" {
		t.Errorf("non-empty UnderlyingVM must produce suffix, got %q", got)
	}
}
