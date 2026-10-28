package render

import (
	"strings"
	"testing"
	"time"

	"github.com/keyorixhq/dashdiag/internal/models"
	"github.com/keyorixhq/dashdiag/internal/output"
	"github.com/keyorixhq/dashdiag/internal/runner"
)

// absentRun is a host with no InfiniBand and no PSI (collectors the registry left
// out, runner.Result.Absent), a Redis whose probe passed but that is not there
// (Detected=false) and a Battery-less desktop (Present=false), next to one check
// that ran.
func absentRun() guardRun {
	return guardRun{
		name: "absent collectors",
		results: []runner.Result{
			{Name: "CPU Load", Data: &models.CPUInfo{}},
			{Name: "InfiniBand", Absent: models.ReasonNotPresent},
			{Name: "Pressure", Absent: models.ReasonNotSupportedPlatform},
			{Name: "Redis", Data: models.RedisInfo{Detected: false}},
			{Name: "Battery", Data: models.BatteryInfo{Present: false}},
		},
	}
}

// TestCoverage_AbsentCollectorsAreNotApplicable: collectors the registry skipped
// and collectors that report absence with Detected/Present count as not applicable
// with their reason, and are never an OK check.
func TestCoverage_AbsentCollectorsAreNotApplicable(t *testing.T) {
	run := absentRun()
	cov := Coverage(run.results, run.insights)
	if cov.Checked != 1 || cov.NotChecked != 0 || cov.NotApplicable != 4 {
		t.Fatalf("checked/not_checked/not_applicable = %d/%d/%d, want 1/0/4", cov.Checked, cov.NotChecked, cov.NotApplicable)
	}
	want := map[string]string{
		"InfiniBand": models.ReasonNotPresent, "Pressure": models.ReasonNotSupportedPlatform,
		"Redis": models.ReasonNotPresent, "Battery": models.ReasonNotPresent,
	}
	for name, reason := range want {
		c := covOf(t, cov, name)
		if c.Coverage != models.CoverageNotApplicable || c.Reason != reason {
			t.Errorf("%s: %q/%q, want not_applicable/%s", name, c.Coverage, c.Reason, reason)
		}
	}
}

// TestAbsentCollectorsReachEveryOutput: each output counts and names them, and none
// lists one as a check.
func TestAbsentCollectorsReachEveryOutput(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	run := absentRun()
	snap := guardSnap(run)
	const line = "1 checked · 4 not applicable"

	outs := map[string]string{
		"terminal": captureStdout(t, func() {
			NewRenderer(output.ModePlain).SetCoverageFrom(snap).PrintSummary(run.insights, time.Second)
		}),
		"markdown":   BuildMarkdownReport(snap, run.insights, time.Second, nil),
		"share text": RenderShareText(snap, run.insights, "Linux"),
	}
	for name, text := range outs {
		if !strings.Contains(text, line) {
			t.Errorf("%s: missing %q in:\n%s", name, line, text)
		}
	}
	if !strings.Contains(outs["markdown"], "InfiniBand") || !strings.Contains(outs["markdown"], "Pressure") {
		t.Errorf("markdown does not name the skipped collectors:\n%s", outs["markdown"])
	}

	out := BuildJSONOutput(run.results, run.insights)
	if out.Coverage.NotApplicable != 4 || len(out.Coverage.NotApplicableChecks) != 4 {
		t.Fatalf("json coverage = %+v, want 4 not applicable", out.Coverage)
	}
	for _, c := range out.Checks {
		if c.Name != "CPU Load" {
			t.Errorf("checks[] lists %q: an absent collector must not be an OK check", c.Name)
		}
	}

	nagios, _ := NagiosLine(run.results, run.insights)
	if !strings.Contains(nagios, "not_applicable=4") {
		t.Errorf("nagios: %s", nagios)
	}
	prom := PrometheusMetrics(run.results, run.insights)
	for _, want := range []string{`dsd_checks_coverage{coverage="not_applicable"} 4`} {
		if !strings.Contains(prom, want) {
			t.Errorf("prometheus missing %q:\n%s", want, prom)
		}
	}
	for _, gone := range []string{"infiniband", "pressure", "redis", "battery"} {
		if strings.Contains(prom, `check="`+gone+`"`) {
			t.Errorf("prometheus has a series for absent %s", gone)
		}
	}
}
