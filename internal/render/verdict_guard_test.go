package render

import (
	"errors"
	"go/ast"
	"go/parser"
	"go/token"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/keyorixhq/dashdiag/internal/analysis"
	"github.com/keyorixhq/dashdiag/internal/baseline"
	"github.com/keyorixhq/dashdiag/internal/models"
	"github.com/keyorixhq/dashdiag/internal/output"
	"github.com/keyorixhq/dashdiag/internal/platform"
	"github.com/keyorixhq/dashdiag/internal/runner"
)

// GUARD A (behaviour) — DD-VERDICT-1, DEFECT-CLASSES.md C1.
//
// Every output of a run must refuse to say "healthy" when the run could not
// verify its own checks. The C1 fix once reached only the exit code, the JSON
// verdict and Nagios; the terminal banner, both reports, the history entry and
// the story kept deriving the verdict from CRIT/WARN counts and printed
// "✅ System healthy" for a run whose collectors had all errored.
//
// The table below is fed two runs that must never read as healthy:
//
//	(a) every collector errored (nothing was measured), and
//	(b) one Unverified INFO and nothing else.
//
// The set of outputs is not a hand-kept list: TestGuardA_OutputsAreAllCovered
// builds it from OutputMode (internal/output) and from the exported
// verdict-bearing functions of this package, so a NEW output mode or renderer
// fails until it is added to the table (or exempted there with a reason).

type guardRun struct {
	name     string
	results  []runner.Result
	insights []models.Insight
}

func guardRuns() []guardRun {
	errored := []runner.Result{
		{Name: "CPU Load", Err: errors.New("reading /proc/stat: permission denied")},
		{Name: "Memory", Err: errors.New("reading /proc/meminfo: permission denied")},
		{Name: "Disk", Err: errors.New("statfs: i/o timeout")},
		{Name: "Network", Err: errors.New("netlink: operation not permitted")},
	}
	thresh := analysis.DefaultThresholds(platform.CloudEnvironment(0))
	allErrored := guardRun{
		name:     "all collectors errored",
		results:  errored,
		insights: analysis.ApplyThresholds(errored, thresh, platform.CloudEnvironment(0), platform.ContainerContext{}),
	}
	oneUnverified := guardRun{
		name:    "one unverified INFO, nothing else",
		results: []runner.Result{{Name: "Logs", Data: &models.CPUInfo{}}},
		insights: []models.Insight{{
			Level: "INFO", Check: "Logs", Unverified: true,
			Message: "kernel log not readable — crash and OOM evidence was not checked",
		}},
	}
	return []guardRun{allErrored, oneUnverified, needsRootPlusOther()}
}

// needsRootInsight is a non-root run's root-only skip (models.Insight.NeedsRoot).
func needsRootInsight(check, msg string) models.Insight {
	return models.Insight{Level: "INFO", Check: check, Unverified: true, NeedsRoot: true, Message: msg}
}

// needsRootOnly is the run the exemption exists for: a non-root run on a stock
// host whose ONLY unverified insights are root-only reads. It is OK for the
// verdict and the exit code, but must say what it skipped (see
// TestGuardA_NeedsRootOnlyRunIsOKWithVisibleSkip).
func needsRootOnly() guardRun {
	return guardRun{
		name:    "non-root, only needs-root unverified",
		results: []runner.Result{{Name: "Hardening", Data: &models.CPUInfo{}}},
		insights: []models.Insight{
			needsRootInsight("Hardening", "/etc/shadow not readable — empty/never-expiring password accounts were NOT audited"),
			needsRootInsight("Logs", "kernel ring buffer (/dev/kmsg) unreadable this run — OOM/segfault counts could not be determined"),
		},
	}
}

// needsRootPlusOther pins the other half: one needs-root skip next to ANY other
// unverified insight is still WARN, never OK/healthy.
func needsRootPlusOther() guardRun {
	r := needsRootOnly()
	r.name = "non-root, needs-root plus one other unverified"
	r.insights = append(r.insights, models.Insight{
		Level: "INFO", Check: "K8s", Unverified: true,
		Message: "kubectl present but the cluster API was unreachable — cluster health NOT verified",
	})
	return r
}

// guardOutput renders one run through one output and returns its text plus an
// extra, output-specific "this is an OK verdict" test (the generic substring
// check below cannot see e.g. `"verdict": "OK"` or `dsd_health_status 0`).
type guardOutput struct {
	name   string
	render func(t *testing.T, r guardRun) string
	okRe   *regexp.Regexp // matches this output's spelling of an OK verdict
}

func guardSnap(r guardRun) *baseline.Snapshot {
	snap := NewSnapshot(r.results, r.insights)
	snap.Hostname = "guard-host"
	snap.Timestamp = time.Date(2026, 10, 27, 12, 0, 0, 0, time.UTC)
	return snap
}

func guardSummary(mode output.OutputMode) func(*testing.T, guardRun) string {
	return func(t *testing.T, r guardRun) string {
		return captureStdout(t, func() { NewRenderer(mode).PrintSummary(r.insights, time.Second) })
	}
}

func guardOutputs() []guardOutput {
	return []guardOutput{
		{"summary/ModeHuman", guardSummary(output.ModeHuman), regexp.MustCompile(`(?m)^✅`)},
		{"summary/ModePlain", guardSummary(output.ModePlain), regexp.MustCompile(`(?m)^OK:`)},
		{"summary/ModeReport", guardSummary(output.ModeReport), regexp.MustCompile(`(?m)^OK:`)},
		{"summary/ModeJSON", func(t *testing.T, r guardRun) string {
			data, err := RenderJSON(r.results, r.insights)
			if err != nil {
				t.Fatal(err)
			}
			return string(data)
		}, regexp.MustCompile(`"verdict":\s*"OK"`)},
		{"summary/ModeYAML", func(t *testing.T, r guardRun) string {
			data, err := RenderYAML(r.results, r.insights)
			if err != nil {
				t.Fatal(err)
			}
			return string(data)
		}, regexp.MustCompile(`(?m)^verdict:\s*"?OK"?\s*$`)},
		{"nagios", func(_ *testing.T, r guardRun) string {
			line, _ := NagiosLine(r.results, r.insights)
			return line
		}, regexp.MustCompile(`^DASHDIAG OK`)},
		{"prometheus", func(_ *testing.T, r guardRun) string {
			return PrometheusMetrics(r.results, r.insights)
		}, regexp.MustCompile(`(?m)^dsd_health_status 0$`)},
		{"markdown report", func(_ *testing.T, r guardRun) string {
			return BuildMarkdownReport(guardSnap(r), r.insights, time.Second, nil)
		}, regexp.MustCompile(`✅ \*\*`)},
		{"html report", func(t *testing.T, r guardRun) string {
			s, err := BuildHTMLReport(guardSnap(r), r.insights, time.Second, nil)
			if err != nil {
				t.Fatal(err)
			}
			return s
		}, regexp.MustCompile(`class="verdict ok"`)},
		{"share text", func(_ *testing.T, r guardRun) string {
			return RenderShareText(guardSnap(r), r.insights, "Linux")
		}, regexp.MustCompile(`Verdict: OK`)},
		{"report text (dsd decode)", func(_ *testing.T, r guardRun) string {
			return RenderReportText(BuildJSONOutput(r.results, r.insights))
		}, regexp.MustCompile(`VERDICT: OK`)},
		{"story (single point)", func(_ *testing.T, r guardRun) string {
			return renderStorySinglePoint(r.insights, guardSnap(r))
		}, nil},
		{"story (history)", func(_ *testing.T, r guardRun) string {
			s := guardSnap(r)
			earlier := *s
			earlier.Timestamp = s.Timestamp.Add(-time.Hour)
			return RenderStoryFromHistory([]*baseline.Snapshot{&earlier, s})
		}, nil},
		{"history entry", func(_ *testing.T, r guardRun) string {
			e := HistoryEntry(guardSnap(r), r.results, r.insights)
			return "verdict=" + e.Verdict
		}, regexp.MustCompile(`verdict=OK`)},
	}
}

var guardBanned = []string{"healthy", "all checks passed", "checks passed"}

func TestGuardA_NoOutputSaysHealthyWhenChecksCouldNotRun(t *testing.T) {
	t.Setenv("HOME", t.TempDir()) // RenderStory-style paths must not read the dev's history
	for _, run := range guardRuns() {
		for _, out := range guardOutputs() {
			t.Run(run.name+"/"+out.name, func(t *testing.T) {
				text := out.render(t, run)
				lower := strings.ToLower(text)
				for _, banned := range guardBanned {
					if strings.Contains(lower, banned) {
						t.Errorf("%s printed %q for a run whose checks could not be verified:\n%s", out.name, banned, text)
					}
				}
				if out.okRe != nil && out.okRe.MatchString(text) {
					t.Errorf("%s reports an OK verdict (%s) for a run whose checks could not be verified:\n%s", out.name, out.okRe, text)
				}
			})
		}
	}
}

// TestGuardA_NeedsRootOnlyRunIsOKWithVisibleSkip pins the exemption for a
// non-root run: root-only reads that could not happen are OK for the verdict
// and the exit code (a stock distro without sudo is not "Not fully verified"
// forever), but every output still names the skip and none says "healthy".
func TestGuardA_NeedsRootOnlyRunIsOKWithVisibleSkip(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	run := needsRootOnly()
	if v := Verdict(run.results, run.insights); v.Level != "OK" || v.ExitCode() != 0 || v.Unverified != 2 || v.NeedsRoot != 2 || v.Skipped != 2 {
		t.Fatalf("Verdict = %+v, want OK / exit 0 / unverified 2 (kept truthful) / needs_root 2 / 2 checks skipped", v)
	}
	for _, out := range guardOutputs() {
		t.Run(out.name, func(t *testing.T) {
			text := out.render(t, run)
			lower := strings.ToLower(text)
			for _, banned := range guardBanned {
				if strings.Contains(lower, banned) {
					t.Errorf("%s printed %q for a run that skipped root-only checks:\n%s", out.name, banned, text)
				}
			}
			if out.okRe != nil && !out.okRe.MatchString(text) {
				t.Errorf("%s does not report an OK verdict (%s) for a needs-root-only run:\n%s", out.name, out.okRe, text)
			}
			// Every human-readable output names the skip; the machine ones carry
			// the count (JSON/YAML needs_root) or only a status number.
			switch out.name {
			case "prometheus", "history entry":
			case "summary/ModeJSON", "summary/ModeYAML":
				if !strings.Contains(text, "needs_root") {
					t.Errorf("%s lost the needs_root count:\n%s", out.name, text)
				}
			default:
				if !strings.Contains(lower, "needs root") {
					t.Errorf("%s does not say what was skipped (want %q):\n%s", out.name, "needs root: N checks skipped", text)
				}
			}
		})
	}
}

// guardCoveredFuncs are the exported functions/methods of this package that
// take a run (insights, results or a snapshot) and present it, mapped to the
// guardOutputs row (or rows) that exercises them. guardExemptFuncs are the
// ones that deliberately carry no overall verdict, each with its reason.
var guardCoveredFuncs = map[string]string{
	"(*Renderer).PrintSummary": "summary/Mode*",
	"RenderJSON":               "summary/ModeJSON",
	"RenderYAML":               "summary/ModeYAML",
	"BuildJSONOutput":          "summary/ModeJSON",
	"NagiosLine":               "nagios",
	"PrometheusMetrics":        "prometheus",
	"BuildMarkdownReport":      "markdown report",
	"GenerateReport":           "markdown report (same builder, writes a file)",
	"BuildHTMLReport":          "html report",
	"GenerateHTMLReport":       "html report (same builder, writes a file)",
	"RenderShareText":          "share text",
	"RenderReportText":         "report text (dsd decode)",
	"RenderStory":              "story (single point) / story (history)",
	"RenderStoryFromHistory":   "story (history)",
	"Verdict":                  "every row — the one derivation they all share",
	"Coverage":                 "coverage_guard_test.go TestGuardC_* — the one coverage derivation every output shares",
	"SnapshotVerdict":          "story (history)",
	"HistoryEntry":             "history entry",
}

var guardExemptFuncs = map[string]string{
	"(*Renderer).PrintAll":        "per-check rows; the overall verdict is PrintSummary's",
	"(*Renderer).PrintAllMock":    "per-check rows; the overall verdict is PrintSummary's",
	"(*Renderer).PrintAllLayered": "per-check rows; the overall verdict is PrintSummary's",
	"(*Renderer).PrintTopCatch":   "top-catch line; says 'none' only when there is no CRIT/WARN finding, never 'healthy'",
	"RenderPostMortem":            "incident write-up listing per-check status rows, no overall verdict line",
	"PrintDiff":                   "diff between two snapshots, prints changes only",
	"ComputeTopCatch":             "top-catch data, no verdict",
	"TopCatchLine":                "top-catch data, no verdict",
	"WithDecodeDisclosure":        "adds a disclosure to a JSONOutput, no verdict",
	"InsightChanges":              "watch-mode delta between two ticks (added/resolved/changed), no overall verdict",
	"PrintInsightChanges":         "watch-mode delta block, prints 'no change', no overall verdict",
	"(*Renderer).SetCoverageFrom": "setter: hands PrintSummary the snapshot's coverage, prints nothing",
	"NewSnapshot":                 "builds baseline.BuildSnapshot + render.Coverage; no verdict line",
}

func TestGuardA_OutputsAreAllCovered(t *testing.T) {
	// 1. Every OutputMode constant must be known to this guard.
	modeCovered := map[string]bool{
		"ModeHuman": true, "ModePlain": true, "ModeReport": true, "ModeJSON": true, "ModeYAML": true,
	}
	for _, name := range outputModeConsts(t) {
		if !modeCovered[name] {
			t.Errorf("output.%s is a new OutputMode: add a summary/%s row to guardOutputs (and a case to guardSummary) before it can ship", name, name)
		}
	}

	// 2. Every exported presenter in this package must be covered or exempt.
	var missing []string
	for _, fn := range exportedPresenters(t) {
		_, covered := guardCoveredFuncs[fn]
		_, exempt := guardExemptFuncs[fn]
		if !covered && !exempt {
			missing = append(missing, fn)
		}
	}
	sort.Strings(missing)
	if len(missing) > 0 {
		t.Errorf("new exported presenter(s) %v take a run but are neither in guardOutputs (guardCoveredFuncs) nor exempted with a reason (guardExemptFuncs) in verdict_guard_test.go: "+
			"an output that prints an overall verdict must go through render.Verdict and appear in the table", missing)
	}
	// And the maps must not rot: every name listed must still exist.
	have := map[string]bool{}
	for _, fn := range exportedPresenters(t) {
		have[fn] = true
	}
	for fn := range guardCoveredFuncs {
		if !have[fn] {
			t.Errorf("guardCoveredFuncs lists %s, which no longer exists/qualifies — remove it", fn)
		}
	}
	for fn := range guardExemptFuncs {
		if !have[fn] {
			t.Errorf("guardExemptFuncs lists %s, which no longer exists/qualifies — remove it", fn)
		}
	}
}

func outputModeConsts(t *testing.T) []string {
	t.Helper()
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, filepath.Join("..", "output", "tty.go"), nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, d := range f.Decls {
		gd, ok := d.(*ast.GenDecl)
		if !ok || gd.Tok != token.CONST {
			continue
		}
		typed := false
		for _, spec := range gd.Specs {
			vs := spec.(*ast.ValueSpec)
			if id, ok := vs.Type.(*ast.Ident); ok && id.Name == "OutputMode" {
				typed = true
			}
			if !typed { // iota continuation specs inherit the type
				continue
			}
			for _, n := range vs.Names {
				names = append(names, n.Name)
			}
		}
	}
	if len(names) == 0 {
		t.Fatal("found no OutputMode constants in internal/output/tty.go — the guard's parser is stale")
	}
	return names
}

// exportedPresenters lists exported functions and methods of this package
// whose parameters include a run: []models.Insight, []runner.Result or a
// *baseline.Snapshot (JSONOutput for the decode path).
func exportedPresenters(t *testing.T) []string {
	t.Helper()
	files, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatal(err)
	}
	var out []string
	for _, file := range files {
		if strings.HasSuffix(file, "_test.go") {
			continue
		}
		f, err := parser.ParseFile(token.NewFileSet(), file, nil, 0)
		if err != nil {
			t.Fatal(err)
		}
		for _, d := range f.Decls {
			fd, ok := d.(*ast.FuncDecl)
			if !ok || !fd.Name.IsExported() || fd.Type.Params == nil {
				continue
			}
			takesRun := false
			for _, p := range fd.Type.Params.List {
				switch typ := exprString(p.Type); typ {
				case "[]models.Insight", "[]runner.Result", "*baseline.Snapshot", "[]*baseline.Snapshot", "JSONOutput":
					takesRun = true
				}
			}
			if !takesRun {
				continue
			}
			name := fd.Name.Name
			if fd.Recv != nil && len(fd.Recv.List) == 1 {
				name = "(" + exprString(fd.Recv.List[0].Type) + ")." + name
			}
			out = append(out, name)
		}
	}
	return out
}

func exprString(e ast.Expr) string {
	switch x := e.(type) {
	case *ast.Ident:
		return x.Name
	case *ast.StarExpr:
		return "*" + exprString(x.X)
	case *ast.ArrayType:
		return "[]" + exprString(x.Elt)
	case *ast.SelectorExpr:
		return exprString(x.X) + "." + x.Sel.Name
	}
	return "?"
}
