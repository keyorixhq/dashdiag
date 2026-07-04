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

func (fakeCollector) Name() string                                   { return "fake" }
func (fakeCollector) Timeout() time.Duration                         { return time.Second }
func (fakeCollector) Collect(_ context.Context) (interface{}, error) { return nil, nil }

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
}

// TestBuildHealthCollectorsGating is a smoke/regression guard on the flat
// collector registry: each opt-in flag should add at least one collector, so
// a future edit that accidentally drops a gated collector from the list
// fails loudly here instead of silently shrinking `dsd health --deep`.
func TestBuildHealthCollectorsGating(t *testing.T) {
	base := buildHealthCollectors(platform.ContainerContext{}, platform.Profile{}, false, false, false, false, false, false)
	if len(base) == 0 {
		t.Fatal("the base collector set must never be empty")
	}
	withPackages := buildHealthCollectors(platform.ContainerContext{}, platform.Profile{}, true, false, false, false, false, false)
	if len(withPackages) <= len(base) {
		t.Errorf("includePackages=true should add at least one collector, base=%d withPackages=%d", len(base), len(withPackages))
	}
	withGPU := buildHealthCollectors(platform.ContainerContext{}, platform.Profile{}, false, true, false, false, false, false)
	if len(withGPU) <= len(base) {
		t.Errorf("includeGPU=true should add at least one collector, base=%d withGPU=%d", len(base), len(withGPU))
	}
}
