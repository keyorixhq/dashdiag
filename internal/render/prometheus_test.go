package render

import (
	"strings"
	"testing"

	"github.com/keyorixhq/dashdiag/internal/models"
	"github.com/keyorixhq/dashdiag/internal/runner"
)

// availResult wraps data the renderer considers "available" (non-nil with a
// recognizable shape). A models pointer with content qualifies via runner.IsAvailable.
func availResult(name string) runner.Result {
	return runner.Result{Name: name, Data: &models.SwapInfo{TotalGB: 1}}
}

func TestPrometheusMetrics(t *testing.T) {
	results := []runner.Result{availResult("Swap"), availResult("Disk"), availResult("CPU Load")}
	insights := []models.Insight{
		{Level: "CRIT", Check: "Disk"},
		{Level: "WARN", Check: "Swap"},
		{Level: "INFO", Check: "CPU Load"}, // INFO → 0
	}
	out := PrometheusMetrics(results, insights)

	// HELP/TYPE present exactly once per metric (valid exposition format).
	for _, h := range []string{
		"# HELP dsd_up", "# TYPE dsd_up gauge",
		"# HELP dsd_check_status", "# TYPE dsd_check_status gauge",
		"# HELP dsd_health_status", "# TYPE dsd_health_status gauge",
	} {
		if strings.Count(out, h) != 1 {
			t.Errorf("expected %q exactly once, got %d:\n%s", h, strings.Count(out, h), out)
		}
	}

	wantSamples := []string{
		"dsd_up 1",
		`dsd_check_status{check="disk"} 2`,
		`dsd_check_status{check="swap"} 1`,
		`dsd_check_status{check="cpu_load"} 0`, // INFO counts as OK
		"dsd_health_status 2",                  // worst is CRIT
	}
	for _, s := range wantSamples {
		if !strings.Contains(out, s) {
			t.Errorf("missing sample %q in:\n%s", s, out)
		}
	}
}

func TestPrometheusSkipsUnavailable(t *testing.T) {
	results := []runner.Result{availResult("Swap"), {Name: "Absent", Data: nil}}
	out := PrometheusMetrics(results, nil)
	if strings.Contains(out, "absent") {
		t.Errorf("absent collector should not emit a series:\n%s", out)
	}
	if !strings.Contains(out, `dsd_check_status{check="swap"} 0`) {
		t.Errorf("available check should emit:\n%s", out)
	}
}

func TestPromLabel(t *testing.T) {
	cases := map[string]string{
		"CPU Load":  "cpu_load",
		"FDLimits":  "fdlimits",
		"K8s":       "k8s",
		"CPU  Load": "cpu_load", // collapse runs
		"  Disk  ":  "disk",     // trim
	}
	for in, want := range cases {
		if got := promLabel(in); got != want {
			t.Errorf("promLabel(%q) = %q, want %q", in, got, want)
		}
	}
}
