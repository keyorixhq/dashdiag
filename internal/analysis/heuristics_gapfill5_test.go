package analysis

import (
	"strings"
	"testing"

	"github.com/keyorixhq/dashdiag/internal/collectors"
	"github.com/keyorixhq/dashdiag/internal/models"
	"github.com/keyorixhq/dashdiag/internal/platform"
	"github.com/keyorixhq/dashdiag/internal/runner"
)

// TestAdaptHostHints_OstreeGate covers the hostIsOstree() → ostreeifyHints() branch
// in AdaptHostHints (line 158 of heuristics.go). Since hostIsOstree reads
// /etc/os-release via collectors.ReadFileViaSource, we inject a fake source.
func TestAdaptHostHints_OstreeGate(t *testing.T) {
	// Not parallel: mutates global source state.
	prev := collectors.SetSource(fakeOSReleaseSource{body: "ID=fedora-coreos\n"})
	defer collectors.SetSource(prev)

	in := []models.Insight{{Hints: []string{
		"to fix: apt install open-vm-tools   (RHEL/SUSE: dnf/zypper install open-vm-tools)",
	}}}
	got := AdaptHostHints(in)
	if len(got) != 1 || len(got[0].Hints) != 1 {
		t.Fatalf("expected 1 insight with 1 hint, got %+v", got)
	}
	if !strings.Contains(got[0].Hints[0], "rpm-ostree") {
		t.Errorf("ostree gate must rewrite hint to rpm-ostree, got %q", got[0].Hints[0])
	}
}

// TestAdaptHostHints_NixOSGate covers the hostIsNixOS() → nixosifyHints() branch
// (line 137 of heuristics.go). hostIsNixOS uses effectiveDistroID which is
// overridable via SetReplayPlatform.
func TestAdaptHostHints_NixOSGate(t *testing.T) {
	// Not parallel: SetReplayPlatform mutates shared package state.
	restore := platform.SetReplayPlatform("nixos", "systemd", "linux")
	defer restore()

	in := []models.Insight{{Hints: []string{
		"to persist: echo 'vm.swappiness=10' >> /etc/sysctl.d/99-dsd.conf",
	}}}
	got := AdaptHostHints(in)
	if len(got) != 1 || len(got[0].Hints) != 1 {
		t.Fatalf("expected 1 insight with 1 hint after NixOS rewrite, got %+v", got)
	}
	if !strings.Contains(got[0].Hints[0], "NixOS") {
		t.Errorf("nixos gate must rewrite hint to NixOS form, got %q", got[0].Hints[0])
	}
}

// TestApplyThresholds_PointerResults covers the *models.SysctlInfo and *models.CPUInfo
// pointer-type arms in ApplyThresholds' cross-inject loop (lines 46 and 53 of
// heuristics.go). Passing these as pointer results is distinct from passing them as
// values; the existing tests only pass value types.
func TestApplyThresholds_PointerResults(t *testing.T) {
	t.Parallel()
	thresh := DefaultThresholds(platform.EnvBareMetal)

	// *models.SysctlInfo pointer — must not panic and must route through applyOne.
	sysctl := &models.SysctlInfo{VMSwappiness: 60}
	sysResults := []runner.Result{{Name: "SysctlCollector", Data: sysctl}}
	_ = ApplyThresholds(sysResults, thresh, platform.EnvBareMetal, platform.ContainerContext{})

	// *models.CPUInfo pointer — same: no panic, correct routing.
	cpu := &models.CPUInfo{LoadPct: 5, NumCPU: 4}
	cpuResults := []runner.Result{{Name: "CPUCollector", Data: cpu}}
	_ = ApplyThresholds(cpuResults, thresh, platform.EnvBareMetal, platform.ContainerContext{})
}
