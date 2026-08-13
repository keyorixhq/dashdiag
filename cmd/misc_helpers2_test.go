package cmd

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/keyorixhq/dashdiag/internal/collectors"
	"github.com/keyorixhq/dashdiag/internal/explain"
	"github.com/keyorixhq/dashdiag/internal/models"
	"github.com/keyorixhq/dashdiag/internal/output"
	"github.com/keyorixhq/dashdiag/internal/platform"
	"github.com/keyorixhq/dashdiag/internal/runner"
)

func TestSeverityRank(t *testing.T) {
	cases := []struct {
		level string
		want  int
	}{
		{"CRIT", 3}, {"WARN", 2}, {"INFO", 1}, {"", 0}, {"weird", 0},
	}
	for _, c := range cases {
		if got := severityRank(c.level); got != c.want {
			t.Errorf("severityRank(%q) = %d, want %d", c.level, got, c.want)
		}
	}
}

func TestParseSinceDuration(t *testing.T) {
	cases := []struct {
		s    string
		want time.Duration
	}{
		{"2d", 48 * time.Hour},
		{"6h", 6 * time.Hour},
		{"", time.Hour}, // unparseable falls back to 1h
		{"not-a-duration", time.Hour},
	}
	for _, c := range cases {
		if got := parseSinceDuration(c.s); got != c.want {
			t.Errorf("parseSinceDuration(%q) = %v, want %v", c.s, got, c.want)
		}
	}
}

// fakeCollector is a minimal collectors.Collector for exercising toRunnerCols'
// pure type conversion without invoking any real collection I/O.
type fakeCollector struct{}

func (fakeCollector) Name() string                           { return "fake" }
func (fakeCollector) Timeout() time.Duration                 { return time.Second }
func (fakeCollector) Collect(_ context.Context) (any, error) { return nil, nil }

func TestToRunnerCols(t *testing.T) {
	in := []collectors.Collector{fakeCollector{}, fakeCollector{}}
	out := toRunnerCols(in)
	if len(out) != 2 {
		t.Fatalf("toRunnerCols should preserve length, got %d", len(out))
	}
	if out[0].Name() != "fake" {
		t.Errorf("converted collector should still satisfy the interface, got name %q", out[0].Name())
	}
}

func TestPrintTopProcsWithCgroup(t *testing.T) {
	if out := captureStdout(t, func() {
		printTopProcsWithCgroup([]runner.Result{{Data: &models.HealthDeepInfo{}}}, output.ModePlain)
	}); out != "" {
		t.Errorf("no top procs should print nothing, got:\n%s", out)
	}

	out := captureStdout(t, func() {
		printTopProcsWithCgroup([]runner.Result{{Data: &models.HealthDeepInfo{
			TopProcs: []models.ProcessMemStat{{PID: 100, Name: "k3s", MemPct: 5.5, CgroupScope: "system:k3s.service"}},
		}}}, output.ModePlain)
	})
	if !strings.Contains(out, "k3s") || !strings.Contains(out, "system:k3s.service") {
		t.Errorf("a top proc should show its name and cgroup scope, got:\n%s", out)
	}

	unknownScope := captureStdout(t, func() {
		printTopProcsWithCgroup([]runner.Result{{Data: &models.HealthDeepInfo{
			TopProcs: []models.ProcessMemStat{{PID: 100, Name: "x"}},
		}}}, output.ModePlain)
	})
	if !strings.Contains(unknownScope, "unknown") {
		t.Errorf("an empty cgroup scope should fall back to unknown, got:\n%s", unknownScope)
	}
}

// TestPrintTopProcsWithCgroup_SanitizesName guards Finding:
// internal-collectors-15-04. p.Name comes from /proc/PID/status "Name:",
// attacker-settable by any unprivileged local process via
// prctl(PR_SET_NAME) or a crafted argv[0].
func TestPrintTopProcsWithCgroup_SanitizesName(t *testing.T) {
	out := captureStdout(t, func() {
		printTopProcsWithCgroup([]runner.Result{{Data: &models.HealthDeepInfo{
			TopProcs: []models.ProcessMemStat{{PID: 100, Name: "\x1b[2Jevil", MemPct: 5.5}},
		}}}, output.ModePlain)
	})
	if strings.ContainsRune(out, 0x1b) {
		t.Errorf("process name output contains a raw ESC byte, got:\n%q", out)
	}
	if !strings.Contains(out, "evil") {
		t.Errorf("printable text around the escape sequence must survive sanitization, got:\n%q", out)
	}
}

// TestPrintTopProcsWithCgroup_StripsControlChars guards terminal escape
// injection: process name and cgroup scope both come from /proc, which is
// attacker-influenced (a process can name itself anything via prctl or
// argv[0]), so raw control bytes must not reach the terminal.
func TestPrintTopProcsWithCgroup_StripsControlChars(t *testing.T) {
	out := captureStdout(t, func() {
		printTopProcsWithCgroup([]runner.Result{{Data: &models.HealthDeepInfo{
			TopProcs: []models.ProcessMemStat{{PID: 100, Name: "evil\x1b]0;pwned\x07", MemPct: 5.5, CgroupScope: "system:k3s.service"}},
		}}}, output.ModePlain)
	})
	if strings.Contains(out, "\x1b") {
		t.Errorf("printTopProcsWithCgroup output still contains ESC byte:\n%s", out)
	}
	if !strings.Contains(out, "evil]0;pwned") {
		t.Errorf("printTopProcsWithCgroup output missing sanitized name:\n%s", out)
	}
}

func TestPrintTopCPUProcsWithCgroup(t *testing.T) {
	if out := captureStdout(t, func() {
		printTopCPUProcsWithCgroup([]runner.Result{{Data: &models.HealthDeepInfo{}}}, output.ModePlain)
	}); out != "" {
		t.Errorf("no top CPU procs should print nothing, got:\n%s", out)
	}

	out := captureStdout(t, func() {
		printTopCPUProcsWithCgroup([]runner.Result{{Data: &models.HealthDeepInfo{
			TopCPUProcs: []models.ProcessCPUStat{{PID: 200, Name: "stress", CPUPct: 88.5, CgroupScope: "system:stress.service"}},
		}}}, output.ModePlain)
	})
	if !strings.Contains(out, "stress") || !strings.Contains(out, "system:stress.service") {
		t.Errorf("a top CPU proc should show its name and cgroup scope, got:\n%s", out)
	}

	unknownScope := captureStdout(t, func() {
		printTopCPUProcsWithCgroup([]runner.Result{{Data: &models.HealthDeepInfo{
			TopCPUProcs: []models.ProcessCPUStat{{PID: 200, Name: "x"}},
		}}}, output.ModePlain)
	})
	if !strings.Contains(unknownScope, "unknown") {
		t.Errorf("an empty cgroup scope should fall back to unknown, got:\n%s", unknownScope)
	}
}

// TestPrintTopCPUProcsWithCgroup_SanitizesName guards the CPU-list half of
// Finding: internal-collectors-15-04 — p.Name comes from /proc/PID/comm,
// attacker-settable the same way.
func TestPrintTopCPUProcsWithCgroup_SanitizesName(t *testing.T) {
	out := captureStdout(t, func() {
		printTopCPUProcsWithCgroup([]runner.Result{{Data: &models.HealthDeepInfo{
			TopCPUProcs: []models.ProcessCPUStat{{PID: 200, Name: "\x1b[2Jevil", CPUPct: 88.5}},
		}}}, output.ModePlain)
	})
	if strings.ContainsRune(out, 0x1b) {
		t.Errorf("process name output contains a raw ESC byte, got:\n%q", out)
	}
	if !strings.Contains(out, "evil") {
		t.Errorf("printable text around the escape sequence must survive sanitization, got:\n%q", out)
	}
}

// TestPrintTopCPUProcsWithCgroup_StripsControlChars mirrors
// TestPrintTopProcsWithCgroup_StripsControlChars for the CPU variant.
func TestPrintTopCPUProcsWithCgroup_StripsControlChars(t *testing.T) {
	out := captureStdout(t, func() {
		printTopCPUProcsWithCgroup([]runner.Result{{Data: &models.HealthDeepInfo{
			TopCPUProcs: []models.ProcessCPUStat{{PID: 200, Name: "evil\x1b]0;pwned\x07", CPUPct: 88.5, CgroupScope: "system:stress.service"}},
		}}}, output.ModePlain)
	})
	if strings.Contains(out, "\x1b") {
		t.Errorf("printTopCPUProcsWithCgroup output still contains ESC byte:\n%s", out)
	}
	if !strings.Contains(out, "evil]0;pwned") {
		t.Errorf("printTopCPUProcsWithCgroup output missing sanitized name:\n%s", out)
	}
}

func TestPrintCgroupUnits(t *testing.T) {
	if out := captureStdout(t, func() {
		printCgroupUnits([]runner.Result{{Data: &models.HealthDeepInfo{}}}, output.ModePlain)
	}); out != "" {
		t.Errorf("no cgroup info should print nothing, got:\n%s", out)
	}
	if out := captureStdout(t, func() {
		printCgroupUnits([]runner.Result{{Data: &models.HealthDeepInfo{Cgroup: &models.CgroupV2Info{}}}}, output.ModePlain)
	}); out != "" {
		t.Errorf("a cgroup summary with no units should print nothing, got:\n%s", out)
	}

	withLimit := captureStdout(t, func() {
		printCgroupUnits([]runner.Result{{Data: &models.HealthDeepInfo{Cgroup: &models.CgroupV2Info{
			Units: []models.CgroupUnit{{
				Name: "postgresql.service", ParentSlice: "system.slice", CPUPct: 12.3,
				MemCurrentMB: 512, MemLimitMB: 1024, HasMemLimit: true,
			}},
		}}}}, output.ModePlain)
	})
	if !strings.Contains(withLimit, "postgresql.service") || !strings.Contains(withLimit, "512/1024MB") {
		t.Errorf("a unit with a memory limit should show current/limit, got:\n%s", withLimit)
	}

	container := captureStdout(t, func() {
		printCgroupUnits([]runner.Result{{Data: &models.HealthDeepInfo{Cgroup: &models.CgroupV2Info{
			Units: []models.CgroupUnit{{Name: "container:abc123", IsContainer: true, MemCurrentMB: 200}},
		}}}}, output.ModePlain)
	})
	if !strings.Contains(container, "container:abc123") || !strings.Contains(container, "200MB") {
		t.Errorf("a container unit should be shown with the 'container' scope label, got:\n%s", container)
	}
	if !strings.Contains(container, "container") {
		t.Errorf("IsContainer=true should label the scope 'container', got:\n%s", container)
	}
}

func TestPrintHealthExplanationsAndFixes(t *testing.T) {
	topics := explain.Topics()
	if len(topics) == 0 {
		t.Skip("no topics available")
	}
	knownCheck := topics[0].Key

	// ModeJSON must render nothing — these are human/plain-only tails.
	if out := captureStdout(t, func() {
		printHealthExplanations([]models.Insight{{Level: "CRIT", Check: knownCheck}}, output.ModeJSON)
	}); out != "" {
		t.Errorf("ModeJSON must not render explanations, got:\n%s", out)
	}

	explOut := captureStdout(t, func() {
		printHealthExplanations([]models.Insight{{Level: "CRIT", Check: knownCheck}}, output.ModePlain)
	})
	if !strings.Contains(explOut, topics[0].Title) {
		t.Errorf("a WARN/CRIT insight matching a known check should explain it, got:\n%s", explOut)
	}

	// An OK-level insight must not be explained (only WARN/CRIT are actionable).
	if out := captureStdout(t, func() {
		printHealthExplanations([]models.Insight{{Level: "OK", Check: knownCheck}}, output.ModePlain)
	}); out != "" {
		t.Errorf("an OK insight should not trigger an explanation, got:\n%s", out)
	}

	fixOut := captureStdout(t, func() {
		printHealthFixes([]models.Insight{{Level: "CRIT", Check: "Disk", Hints: []string{"to fix: resize2fs /dev/sda1"}}}, output.ModePlain)
	})
	if !strings.Contains(fixOut, "resize2fs") {
		t.Errorf("a fix hint should be consolidated into the fixes block, got:\n%s", fixOut)
	}

	// ModeHuman exercises the lipgloss-styled bold/dim branches of both tails.
	explHuman := captureStdout(t, func() {
		printHealthExplanations([]models.Insight{{Level: "CRIT", Check: knownCheck}}, output.ModeHuman)
	})
	if !strings.Contains(explHuman, topics[0].Title) {
		t.Errorf("ModeHuman should still explain a WARN/CRIT insight, got:\n%s", explHuman)
	}
	fixHuman := captureStdout(t, func() {
		printHealthFixes([]models.Insight{{Level: "CRIT", Check: "Disk", Hints: []string{"to fix: resize2fs /dev/sda1"}}}, output.ModeHuman)
	})
	if !strings.Contains(fixHuman, "resize2fs") {
		t.Errorf("ModeHuman should still render the fixes block, got:\n%s", fixHuman)
	}

	// ModeJSON must render nothing for printHealthFixes too (human/plain-only tail).
	if out := captureStdout(t, func() {
		printHealthFixes([]models.Insight{{Level: "CRIT", Check: "Disk", Hints: []string{"to fix: resize2fs /dev/sda1"}}}, output.ModeJSON)
	}); out != "" {
		t.Errorf("ModeJSON must not render fixes, got:\n%s", out)
	}

	// No WARN/CRIT insight with a "to fix:" hint at all → the fixes block is
	// entirely omitted (not just an empty heading).
	if out := captureStdout(t, func() {
		printHealthFixes([]models.Insight{{Level: "OK", Check: "Disk"}}, output.ModePlain)
	}); out != "" {
		t.Errorf("no fix-worthy insights should print nothing, got:\n%s", out)
	}

	// A WARN/CRIT insight whose Check has no matching explain topic yields no
	// matched entries, so printHealthExplanations prints nothing.
	if out := captureStdout(t, func() {
		printHealthExplanations([]models.Insight{{Level: "CRIT", Check: "zzz-unknown-check-zzz"}}, output.ModePlain)
	}); out != "" {
		t.Errorf("an unmatched check should print nothing, got:\n%s", out)
	}
}

// TestBuildHealthCollectorsGating is a smoke/regression guard on the flat
// collector registry: each opt-in flag should add at least one collector, so
// a future edit that accidentally drops a gated collector from the list
// fails loudly here instead of silently shrinking `dsd health --deep`.
func TestBuildHealthCollectorsGating(t *testing.T) {
	base := buildHealthCollectors(platform.ContainerContext{}, platform.Profile{}, healthRunOpts{})
	if len(base) == 0 {
		t.Fatal("the base collector set must never be empty")
	}
	withPackages := buildHealthCollectors(platform.ContainerContext{}, platform.Profile{}, healthRunOpts{IncludePackages: true})
	if len(withPackages) <= len(base) {
		t.Errorf("includePackages=true should add at least one collector, base=%d withPackages=%d", len(base), len(withPackages))
	}
	withGPU := buildHealthCollectors(platform.ContainerContext{}, platform.Profile{}, healthRunOpts{IncludeGPU: true})
	if len(withGPU) <= len(base) {
		t.Errorf("includeGPU=true should add at least one collector, base=%d withGPU=%d", len(base), len(withGPU))
	}
	withTLS := buildHealthCollectors(platform.ContainerContext{}, platform.Profile{}, healthRunOpts{IncludeTLS: true})
	if len(withTLS) <= len(base) {
		t.Errorf("includeTLS=true should add at least one collector, base=%d withTLS=%d", len(base), len(withTLS))
	}
	withDeep := buildHealthCollectors(platform.ContainerContext{}, platform.Profile{}, healthRunOpts{IncludeDeep: true})
	if len(withDeep) <= len(base) {
		t.Errorf("includeDeep=true should add at least one collector, base=%d withDeep=%d", len(base), len(withDeep))
	}
	withFirmware := buildHealthCollectors(platform.ContainerContext{}, platform.Profile{}, healthRunOpts{IncludeFirmware: true})
	if len(withFirmware) <= len(base) {
		t.Errorf("includeFirmware=true should add at least one collector, base=%d withFirmware=%d", len(base), len(withFirmware))
	}
	withCVE := buildHealthCollectors(platform.ContainerContext{}, platform.Profile{}, healthRunOpts{IncludeCVE: true})
	if len(withCVE) <= len(base) {
		t.Errorf("includeCVE=true should add at least one collector, base=%d withCVE=%d", len(base), len(withCVE))
	}
	// includeDeep swaps the plain NetworkCollector for NetworkDeepCollector —
	// same slot, so deep mode's collector count isn't guaranteed to exceed a
	// packages-only run by more than one; this just guards the swap doesn't
	// silently drop network collection entirely.
	inContainer := buildHealthCollectors(platform.ContainerContext{InContainer: true}, platform.Profile{}, healthRunOpts{})
	if len(inContainer) == 0 {
		t.Error("a container context must still produce a non-empty collector set")
	}
}
