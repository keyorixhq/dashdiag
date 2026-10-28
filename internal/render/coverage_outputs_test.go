package render

import (
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/keyorixhq/dashdiag/internal/models"
	"github.com/keyorixhq/dashdiag/internal/output"
	"github.com/keyorixhq/dashdiag/internal/runner"
)

// coverageRun is a run with one of everything: a checked check, a partially
// checked one (root-only part skipped), a collector that timed out, and two
// collectors with nothing to check. Every output must say so.
func coverageRun() guardRun {
	return guardRun{
		name: "mixed coverage",
		results: []runner.Result{
			{Name: "CPU Load", Data: &models.CPUInfo{}},
			{Name: "Hardening", Data: &models.CPUInfo{}},
			{Name: "Memory", Err: errors.New("collector Memory timed out after 2s")},
			{Name: "GPU"},
			{Name: "Docker", Data: models.DockerInfo{Available: false}},
		},
		insights: []models.Insight{
			needsRootInsight("Hardening", "/etc/shadow not readable — accounts were NOT audited"),
			{Level: "INFO", Check: "Memory", Unverified: true, Message: "check could not run — timed out"},
		},
	}
}

const wantCoverageLine = "2 checked · 2 not checked (needs root: 1, timeout: 1) · 2 not applicable"

// TestCoverageReachesEveryOutput: each output of the same run names what was
// not checked, with the reason, and the human ones with the action.
func TestCoverageReachesEveryOutput(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	run := coverageRun()
	snap := guardSnap(run)

	humanOutputs := map[string]string{
		"terminal human": captureStdout(t, func() {
			NewRenderer(output.ModeHuman).SetCoverageFrom(snap).PrintSummary(run.insights, time.Second)
		}),
		"terminal plain": captureStdout(t, func() {
			NewRenderer(output.ModePlain).SetCoverageFrom(snap).PrintSummary(run.insights, time.Second)
		}),
		"markdown":   BuildMarkdownReport(snap, run.insights, time.Second, nil),
		"share text": RenderShareText(snap, run.insights, "Linux"),
	}
	html, err := BuildHTMLReport(snap, run.insights, time.Second, nil)
	if err != nil {
		t.Fatal(err)
	}
	humanOutputs["html"] = html
	humanOutputs["decode text"] = RenderReportText(BuildJSONOutput(run.results, run.insights))

	for name, text := range humanOutputs {
		t.Run(name, func(t *testing.T) {
			if !strings.Contains(text, wantCoverageLine) {
				t.Errorf("missing coverage line %q in:\n%s", wantCoverageLine, text)
			}
			for _, want := range []string{"Memory", "timeout", "Hardening", "needs root", "re-run with sudo"} {
				if !strings.Contains(text, want) {
					t.Errorf("missing %q in:\n%s", want, text)
				}
			}
		})
	}

	// Not-applicable is compact: named in the reports, only counted on the terminal.
	for _, name := range []string{"markdown", "html"} {
		if !strings.Contains(humanOutputs[name], "Docker, GPU") {
			t.Errorf("%s does not name the not-applicable collectors:\n%s", name, humanOutputs[name])
		}
	}

	nagios, _ := NagiosLine(run.results, run.insights)
	for _, want := range []string{"| checked=2 not_checked=2 not_applicable=2", "NOT CHECKED: Memory (timeout", "NOT CHECKED: Hardening (needs root, re-run with sudo)"} {
		if !strings.Contains(nagios, want) {
			t.Errorf("nagios missing %q:\n%s", want, nagios)
		}
	}

	prom := PrometheusMetrics(run.results, run.insights)
	for _, want := range []string{
		`dsd_checks_coverage{coverage="checked"} 2`, `dsd_checks_coverage{coverage="not_checked"} 2`, `dsd_checks_coverage{coverage="not_applicable"} 2`,
		`dsd_checks_not_checked{reason="needs_root"} 1`, `dsd_checks_not_checked{reason="timeout"} 1`,
		`dsd_check_checked{check="memory"} 0`, `dsd_check_checked{check="hardening"} 1`, `dsd_check_checked{check="cpu_load"} 1`,
	} {
		if !strings.Contains(prom, want) {
			t.Errorf("prometheus missing %q:\n%s", want, prom)
		}
	}
	if strings.Contains(prom, `dsd_check_checked{check="gpu"}`) {
		t.Error("a not-applicable collector must have no dsd_check_checked series")
	}

	for name, render := range map[string]func() ([]byte, error){
		"json": func() ([]byte, error) { return RenderJSON(run.results, run.insights) },
		"yaml": func() ([]byte, error) { return RenderYAML(run.results, run.insights) },
	} {
		data, err := render()
		if err != nil {
			t.Fatal(err)
		}
		text := string(data)
		for _, want := range []string{"coverage", "coverage_reason", "not_checked_subchecks", "not_applicable_checks"} {
			if !strings.Contains(text, want) {
				t.Errorf("%s missing %q:\n%s", name, want, text)
			}
		}
	}
}

// TestCoverageFallsBackToInsightsWithoutASnapshotCoverage: a snapshot stored
// before coverage existed still lists what was not checked (from the insights),
// and leaves out the counts it cannot know.
func TestCoverageFallsBackToInsightsWithoutASnapshotCoverage(t *testing.T) {
	run := coverageRun()
	snap := guardSnap(run)
	snap.Coverage = nil

	md := BuildMarkdownReport(snap, run.insights, time.Second, nil)
	if !strings.Contains(md, "`Hardening` — needs root") || !strings.Contains(md, "`Memory` — unverified") {
		t.Errorf("legacy snapshot lost the not-checked list:\n%s", md)
	}
	if strings.Contains(md, " checked ·") {
		t.Errorf("legacy snapshot printed counts it cannot know:\n%s", md)
	}
}

// TestCoverageNothingToSayPrintsNothing: a clean run with nothing skipped keeps
// its quiet terminal output apart from the one coverage line.
func TestCoverageNothingToSayPrintsNothing(t *testing.T) {
	results := []runner.Result{{Name: "CPU Load", Data: &models.CPUInfo{}}}
	snap := NewSnapshot(results, nil)
	out := captureStdout(t, func() { NewRenderer(output.ModePlain).SetCoverageFrom(snap).PrintSummary(nil, time.Second) })
	if strings.Contains(out, "NOT CHECKED") {
		t.Errorf("clean run printed a Not checked group:\n%s", out)
	}
	if !strings.Contains(out, "Coverage: 1 checked") {
		t.Errorf("clean run lost the coverage line:\n%s", out)
	}
}
