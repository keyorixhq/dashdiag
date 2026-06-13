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

// TestPrometheusQualifiedCheckRollup pins that a subsystem-qualified insight Check
// (e.g. "Network/DNS") rolls its severity up to the base collector's per-check
// metric. Before, a DNS-only CRIT left dsd_check_status{check="network"} at 0 even
// though dsd_health_status was 2 — a false-OK in the per-check series that a
// monitoring alert keyed on `check="network"` would silently miss.
func TestPrometheusQualifiedCheckRollup(t *testing.T) {
	results := []runner.Result{availResult("Network"), availResult("Memory"), availResult("CPU Load")}
	insights := []models.Insight{
		{Level: "CRIT", Check: "Network/DNS"},    // qualified -> rolls into Network
		{Level: "WARN", Check: "Memory/Slab"},    // qualified -> rolls into Memory
		{Level: "CRIT", Check: "CPU Load/Steal"}, // qualified -> rolls into CPU Load
	}
	out := PrometheusMetrics(results, insights)
	for _, s := range []string{
		`dsd_check_status{check="network"} 2`,
		`dsd_check_status{check="memory"} 1`,
		`dsd_check_status{check="cpu_load"} 2`,
		"dsd_health_status 2",
	} {
		if !strings.Contains(out, s) {
			t.Errorf("missing sample %q in:\n%s", s, out)
		}
	}
	if strings.Contains(out, `check="network_dns"`) {
		t.Errorf("qualified Check must not emit its own series:\n%s", out)
	}
}
