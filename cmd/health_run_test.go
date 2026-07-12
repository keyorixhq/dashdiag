package cmd

// health_run_test.go covers health.go's extracted helper functions directly.
// It deliberately does NOT call runHealth() through its full body: the tail
// of runHealth ends in `if exitCode > 0 { os.Exit(exitCode) }`, gated on real
// collector-derived severity that can't be forced clean in this sandboxed
// container — an in-process os.Exit would abort the whole test binary, not
// just this test. That's the same "os.Exit path is legitimately untestable
// in this harness" carve-out documented in baseline_run_test.go. Instead this
// file exercises every extracted piece runHealth wires together (per the
// file's own doc comments — they were split out for exactly this reason),
// plus the two branches of runHealth itself that return before reaching that
// tail: a policy-load error, and --story with enough history already saved.

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/spf13/cobra"

	"github.com/keyorixhq/dashdiag/internal/analysis"
	"github.com/keyorixhq/dashdiag/internal/baseline"
	"github.com/keyorixhq/dashdiag/internal/models"
	"github.com/keyorixhq/dashdiag/internal/output"
	"github.com/keyorixhq/dashdiag/internal/platform"
	"github.com/keyorixhq/dashdiag/internal/render"
	"github.com/keyorixhq/dashdiag/internal/runner"
	"github.com/keyorixhq/dashdiag/internal/tips"
)

func TestHealthOutputMode(t *testing.T) {
	t.Parallel()
	newCmd := func(plain, jsonOut, yamlOut, blob, nagios, prom bool) *cobra.Command {
		c := &cobra.Command{}
		f := c.Flags()
		f.Bool("plain", plain, "")
		f.Bool("json", jsonOut, "")
		f.Bool("yaml", yamlOut, "")
		f.Bool("blob", blob, "")
		f.Bool("nagios", nagios, "")
		f.Bool("prometheus", prom, "")
		return c
	}
	// "default" isn't asserted as ModeHuman: healthOutputMode delegates the
	// human/plain choice to output.DetectMode, which falls back to ModePlain
	// whenever stdout isn't a TTY (see tty.go) — true for every `go test` run,
	// same reason the project requires --plain to work in CI. That leaves the
	// nagios/prometheus "downgrade human to plain" branch unreachable from
	// this harness too (there's no way to present a real TTY to DetectMode),
	// so those cases below assert the actually-observable outcome (ModePlain)
	// rather than exercising the downgrade branch itself.
	cases := []struct {
		name                                   string
		plain, jsonOut, yamlOut, blob, n, prom bool
		want                                   output.OutputMode
	}{
		{"plain", true, false, false, false, false, false, output.ModePlain},
		{"json", false, true, false, false, false, false, output.ModeJSON},
		{"yaml", false, false, true, false, false, false, output.ModeYAML},
		{"blob acts as json", false, false, false, true, false, false, output.ModeJSON},
		{"nagios, non-tty already plain", false, false, false, false, true, false, output.ModePlain},
		{"prometheus, non-tty already plain", false, false, false, false, false, true, output.ModePlain},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			t.Parallel()
			cmd := newCmd(c.plain, c.jsonOut, c.yamlOut, c.blob, c.n, c.prom)
			if got := healthOutputMode(cmd); got != c.want {
				t.Errorf("healthOutputMode(%+v) = %v, want %v", c, got, c.want)
			}
		})
	}
}

func TestApplyHealthPolicyGate(t *testing.T) {
	// nil policy: exit code passes through unchanged.
	if got := applyHealthPolicyGate(nil, "", output.ModePlain, nil, 0); got != 0 {
		t.Errorf("nil policy should not change exit code, got %d", got)
	}

	policy := &analysis.PolicyFile{Deny: []string{"WARN"}}
	insights := []models.Insight{{Level: "WARN", Check: "Swap"}}
	if got := applyHealthPolicyGate(policy, "", output.ModePlain, insights, 0); got != 1 {
		t.Errorf("a policy denying WARN should raise exit 0 to 1, got %d", got)
	}
	// Exit code already non-zero: gate must not lower it.
	if got := applyHealthPolicyGate(policy, "", output.ModePlain, insights, 2); got != 2 {
		t.Errorf("the gate must not lower an existing exit code, got %d", got)
	}

	stderr := captureStderr(t, func() {
		applyHealthPolicyGate(policy, "policy.yaml", output.ModeHuman, insights, 0)
	})
	if !strings.Contains(stderr, "policy.yaml") {
		t.Errorf("a named policy in human mode should print a banner naming the file, got: %q", stderr)
	}
}

func TestLoadPolicyIfSet(t *testing.T) {
	p, err := loadPolicyIfSet("")
	if p != nil || err != nil {
		t.Errorf("empty path should return (nil, nil), got (%v, %v)", p, err)
	}

	stderr := captureStderr(t, func() {
		_, err := loadPolicyIfSet(filepath.Join(t.TempDir(), "no-such-policy.yaml"))
		if err == nil {
			t.Error("a missing policy file should error")
		}
	})
	if !strings.Contains(stderr, "policy error") {
		t.Errorf("a policy load error should be reported on stderr, got: %q", stderr)
	}
}

func TestPrintHealthFooterVariants(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	t.Setenv("DSD_NO_UPDATE_CHECK", "1")

	// Plain mode with elapsed>0: prints the timing line, no state.
	out := captureStdout(t, func() {
		printHealthFooter(output.ModePlain, false, nil, 2*time.Second)
	})
	if !strings.Contains(out, "done in 2.0s") {
		t.Errorf("plain mode should print the timing line, got: %q", out)
	}

	// elapsed==0: no timing line at all.
	none := captureStdout(t, func() {
		printHealthFooter(output.ModePlain, false, nil, 0)
	})
	if strings.Contains(none, "done in") {
		t.Errorf("elapsed==0 should print no timing line, got: %q", none)
	}

	// With state: command count increments and is saved.
	state := &tips.State{}
	captureStdout(t, func() {
		printHealthFooter(output.ModePlain, false, state, time.Second)
	})
	if state.CommandCounts["health"] != 1 {
		t.Errorf("printHealthFooter should increment the health command count, got %d", state.CommandCounts["health"])
	}

	// qrFlag=true with an empty share URL is a no-op (doesn't panic/error).
	captureStdout(t, func() {
		printHealthFooter(output.ModeHuman, true, nil, 0)
	})

	// ModeHuman with elapsed>0: the styled (lipgloss-dim) timing line — a
	// distinct branch from the ModePlain timing line above.
	human := captureStdout(t, func() {
		printHealthFooter(output.ModeHuman, false, nil, 3*time.Second)
	})
	if !strings.Contains(human, "done in 3.0s") {
		t.Errorf("human mode should print the styled timing line, got: %q", human)
	}
}

func TestWriteHealthReports(t *testing.T) {
	dir := t.TempDir()
	old, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chdir(dir); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = os.Chdir(old) }()

	ctx := context.Background()
	insights := []models.Insight{{Level: "WARN", Check: "Swap", Message: "swap high"}}

	// Neither flag set: no-op.
	var buf bytes.Buffer
	writeHealthReports(ctx, false, false, &baseline.Snapshot{Hostname: "h"}, insights, time.Second, &buf)
	if buf.Len() != 0 {
		t.Errorf("neither --report nor --report-html should write anything, got: %q", buf.String())
	}

	// nil snapshot: no-op even with a flag set.
	writeHealthReports(ctx, true, false, nil, insights, time.Second, &buf)
	if buf.Len() != 0 {
		t.Errorf("a nil snapshot should skip report generation, got: %q", buf.String())
	}

	snap := &baseline.Snapshot{Hostname: "test-host", Timestamp: time.Now()}
	writeHealthReports(ctx, true, true, snap, insights, time.Second, &buf)
	out := buf.String()
	if !strings.Contains(out, "Report saved") || !strings.Contains(out, "HTML report saved") {
		t.Errorf("both --report and --report-html should confirm their saved paths, got: %q", out)
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) < 2 {
		t.Errorf("expected at least 2 report files written, got %d entries", len(entries))
	}
}

// TestWriteHealthReports_WriteErrors covers writeHealthReports' error paths:
// GenerateReport/GenerateHTMLReport fail (surfaced to stderr, not noticeW)
// when their deterministic output filename is pre-occupied by a directory —
// neither exercised by TestWriteHealthReports' clean-write case above.
func TestWriteHealthReports_WriteErrors(t *testing.T) {
	dir := t.TempDir()
	old, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chdir(dir); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = os.Chdir(old) }()

	ctx := context.Background()
	insights := []models.Insight{{Level: "WARN", Check: "Swap", Message: "swap high"}}
	snap := &baseline.Snapshot{Hostname: "test-host", Timestamp: time.Now()}

	mdPath := fmt.Sprintf("dsd-report-%s-%s.md", snap.Hostname, snap.Timestamp.Format("20060102-150405"))
	htmlPath := fmt.Sprintf("dsd-report-%s-%s.html", snap.Hostname, snap.Timestamp.Format("20060102-150405"))
	if err := os.Mkdir(mdPath, 0o750); err != nil {
		t.Fatalf("pre-creating blocking dir for md report: %v", err)
	}
	if err := os.Mkdir(htmlPath, 0o750); err != nil {
		t.Fatalf("pre-creating blocking dir for html report: %v", err)
	}

	var buf bytes.Buffer
	stderr := captureStderr(t, func() {
		writeHealthReports(ctx, true, true, snap, insights, time.Second, &buf)
	})
	if buf.Len() != 0 {
		t.Errorf("a failed report write must not print a saved-path notice, got: %q", buf.String())
	}
	if !strings.Contains(stderr, "report:") {
		t.Errorf("a failed report write should surface the error on stderr, got: %q", stderr)
	}
}

func TestHandleNagiosModeCleanRun(t *testing.T) {
	defer func() { pendingExitCode = 0 }()

	handled, err := handleNagiosMode(false, nil, nil, nil)
	if handled || err != nil {
		t.Errorf("nagiosFlag=false should not be handled, got handled=%v err=%v", handled, err)
	}

	// Empty insights → Nagios exit code 0, so handleNagiosMode returns
	// normally instead of calling os.Exit (the code>0 branch is the
	// untestable os.Exit path).
	out := captureStdout(t, func() {
		handled, err = handleNagiosMode(true, nil, nil, &baseline.Snapshot{Hostname: "h"})
	})
	if !handled || err != nil {
		t.Errorf("a clean run should be handled with no error, got handled=%v err=%v", handled, err)
	}
	if !strings.Contains(out, "OK") {
		t.Errorf("a clean Nagios line should say OK, got: %q", out)
	}
}

func TestHandlePrometheusMode(t *testing.T) {
	handled, err := handlePrometheusMode(false, nil, nil, nil)
	if handled || err != nil {
		t.Errorf("promFlag=false should not be handled, got handled=%v err=%v", handled, err)
	}

	out := captureStdout(t, func() {
		handled, err = handlePrometheusMode(true, nil, nil, &baseline.Snapshot{Hostname: "h"})
	})
	if !handled || err != nil {
		t.Errorf("promFlag=true should be handled with no error, got handled=%v err=%v", handled, err)
	}
	if out == "" {
		t.Error("prometheus mode should emit metrics text")
	}
}

func TestHandleBlobMode(t *testing.T) {
	handled, err := handleBlobMode(false, nil, nil, nil)
	if handled || err != nil {
		t.Errorf("blobFlag=false should not be handled, got handled=%v err=%v", handled, err)
	}

	stdout := captureStdout(t, func() {
		stderr := captureStderr(t, func() {
			handled, err = handleBlobMode(true, nil, nil, &baseline.Snapshot{Hostname: "h"})
		})
		if !strings.Contains(stderr, "Copy the whole block") {
			t.Errorf("blob mode should print copy instructions to stderr, got: %q", stderr)
		}
	})
	if !handled || err != nil {
		t.Errorf("blobFlag=true should be handled with no error, got handled=%v err=%v", handled, err)
	}
	if stdout == "" {
		t.Error("blob mode should emit the encoded block to stdout")
	}
}

// TestHandleBlobMode_RenderJSONErrorPropagates covers handleBlobMode's error
// path: a result whose Data can't be JSON-marshalled (an unmarshalable
// channel type) makes render.RenderJSON fail, and that error must propagate
// wrapped, not be silently swallowed.
func TestHandleBlobMode_RenderJSONErrorPropagates(t *testing.T) {
	badResults := []runner.Result{{Name: "Bad", Data: make(chan int)}}
	_, err := handleBlobMode(true, badResults, nil, &baseline.Snapshot{Hostname: "h"})
	if err == nil {
		t.Fatal("an unmarshalable result should make handleBlobMode return an error")
	}
	if !strings.Contains(err.Error(), "blob:") {
		t.Errorf("error should be wrapped with 'blob:' context, got: %v", err)
	}
}

func TestHandleWeeklyMode(t *testing.T) {
	t.Setenv("HOME", t.TempDir())

	handled, err := handleWeeklyMode(false)
	if handled || err != nil {
		t.Errorf("weeklyFlag=false should not be handled, got handled=%v err=%v", handled, err)
	}

	notEnough := captureStdout(t, func() {
		handled, err = handleWeeklyMode(true)
	})
	if !handled || err != nil {
		t.Errorf("weeklyFlag=true with no state should be handled with no error, got handled=%v err=%v", handled, err)
	}
	if !strings.Contains(notEnough, "Not enough data") {
		t.Errorf("no saved state should say not enough data, got: %q", notEnough)
	}

	state := &tips.State{TotalRuns: 10, CommandCounts: map[string]int{}}
	if err := state.Save(); err != nil {
		t.Fatalf("saving fixture state: %v", err)
	}
	enough := captureStdout(t, func() {
		handled, err = handleWeeklyMode(true)
	})
	if !handled || err != nil {
		t.Errorf("weeklyFlag=true with enough runs should be handled with no error, got handled=%v err=%v", handled, err)
	}
	if enough == "" {
		t.Error("enough history should render a weekly report")
	}
}

func TestHandlePostMortemMode(t *testing.T) {
	t.Setenv("HOME", t.TempDir())

	handled, err := handlePostMortemMode("", nil, nil, output.ModePlain)
	if handled || err != nil {
		t.Errorf("empty incident id should not be handled, got handled=%v err=%v", handled, err)
	}

	snap := &baseline.Snapshot{Hostname: "h", Timestamp: time.Now()}
	out := captureStdout(t, func() {
		handled, err = handlePostMortemMode("incident-1", snap, nil, output.ModePlain)
	})
	if !handled || err != nil {
		t.Errorf("a given incident id should be handled with no error, got handled=%v err=%v", handled, err)
	}
	if out == "" {
		t.Error("post-mortem mode should render a report")
	}
}

func TestPrintHealthDiffNotice(t *testing.T) {
	t.Setenv("HOME", t.TempDir())

	// diffFlag=false: no-op.
	var buf bytes.Buffer
	printHealthDiffNotice(&buf, false, nil, output.ModePlain)
	if buf.Len() != 0 {
		t.Errorf("diffFlag=false should print nothing, got: %q", buf.String())
	}

	// No previous baseline saved yet: an informational notice on stderr.
	stderr := captureStderr(t, func() {
		printHealthDiffNotice(os.Stderr, true, &baseline.Snapshot{Hostname: "h"}, output.ModePlain)
	})
	if !strings.Contains(stderr, "No previous baseline") {
		t.Errorf("with no saved baseline, expected a notice, got: %q", stderr)
	}

	// A previous baseline exists: PrintDiff runs instead. LoadBaseline("")
	// reads back by the REAL os.Hostname() (it ignores the snapshot's own
	// Hostname field), so the seeded baseline must use it too.
	hostname, _ := os.Hostname()
	prev := &baseline.Snapshot{Hostname: hostname, Timestamp: time.Now(), Checks: []baseline.CheckResult{{Name: "CPU", Status: "OK"}}}
	if err := baseline.SaveBaseline(prev); err != nil {
		t.Fatalf("seeding a baseline: %v", err)
	}
	cur := &baseline.Snapshot{Hostname: hostname, Timestamp: time.Now(), Checks: []baseline.CheckResult{{Name: "CPU", Status: "WARN"}}}
	buf.Reset()
	printHealthDiffNotice(&buf, true, cur, output.ModePlain)
	if buf.Len() == 0 {
		t.Error("with a saved baseline, PrintDiff should write a diff")
	}
}

// TestPrintHealthResults covers the printHealthResults orchestrator: it
// wires CorrelateDeep + printHealthMainOutput + PrintSummary + baseline save
// together, and its noticeW routing (stdout for human/plain, stderr for
// JSON/YAML so the machine document stays a single parseable stream).
func TestPrintHealthResults(t *testing.T) {
	t.Setenv("HOME", t.TempDir())

	results := []runner.Result{{Name: "CPU Load", Data: &models.CPUInfo{}}}
	insights := []models.Insight{{Level: "OK", Check: "CPU Load"}}
	snap := &baseline.Snapshot{Hostname: "h", Timestamp: time.Now()}

	newCmd := func() *cobra.Command {
		c := &cobra.Command{}
		f := c.Flags()
		f.Bool("layered", false, "")
		f.Bool("diff", false, "")
		f.Bool("explain", false, "")
		f.Bool("fix", false, "")
		return c
	}

	var exitCode int
	out := captureStdout(t, func() {
		var noticeW any
		exitCode, noticeW = printHealthResults(newCmd(), platform.ContainerContext{}, output.ModePlain, results, insights, snap, time.Second, false)
		if noticeW != os.Stdout {
			t.Error("human/plain mode should route notices to stdout")
		}
	})
	if exitCode != 0 {
		t.Errorf("all-OK insights should yield exit code 0, got %d", exitCode)
	}
	if !strings.Contains(out, "CPU Load") {
		t.Errorf("plain mode should render the results, got: %q", out)
	}

	// JSON mode routes notices to stderr instead.
	captureStdout(t, func() {
		_, noticeW := printHealthResults(newCmd(), platform.ContainerContext{}, output.ModeJSON, results, insights, snap, time.Second, false)
		if noticeW != os.Stderr {
			t.Error("JSON mode should route notices to stderr, keeping stdout a single document")
		}
	})

	// In-container: the container banner path.
	bannerOut := captureStdout(t, func() {
		printHealthResults(newCmd(), platform.ContainerContext{InContainer: true}, output.ModePlain, results, insights, snap, time.Second, false)
	})
	if bannerOut == "" {
		t.Error("an in-container run should still render output")
	}

	// explain + fix flags on a WARN insight exercise both tail sections.
	c := newCmd()
	_ = c.Flags().Set("explain", "true")
	_ = c.Flags().Set("fix", "true")
	warnInsights := []models.Insight{{Level: "WARN", Check: "cpu", Hints: []string{"to fix: renice the offending process"}}}
	tailOut := captureStdout(t, func() {
		printHealthResults(c, platform.ContainerContext{}, output.ModePlain, results, warnInsights, snap, time.Second, false)
	})
	if !strings.Contains(tailOut, "renice the offending process") {
		t.Errorf("--fix should append the remediation command, got: %q", tailOut)
	}
}

func TestPrintHealthMainOutputModes(t *testing.T) {
	results := []runner.Result{{Name: "CPU Load", Data: &models.CPUInfo{}}}
	insights := []models.Insight{{Level: "OK", Check: "CPU Load"}}

	jsonOut := captureStdout(t, func() {
		r := render.NewRenderer(output.ModeJSON)
		printHealthMainOutput(r, output.ModeJSON, results, insights, nil, false, false)
	})
	if !strings.Contains(jsonOut, `"checks"`) {
		t.Errorf("JSON mode should emit the JSON document, got: %q", jsonOut)
	}

	yamlOut := captureStdout(t, func() {
		r := render.NewRenderer(output.ModeYAML)
		printHealthMainOutput(r, output.ModeYAML, results, insights, nil, false, false)
	})
	if yamlOut == "" {
		t.Error("YAML mode should emit a document")
	}

	plainOut := captureStdout(t, func() {
		r := render.NewRenderer(output.ModePlain)
		printHealthMainOutput(r, output.ModePlain, results, insights, nil, false, false)
	})
	if !strings.Contains(plainOut, "CPU Load") {
		t.Errorf("plain mode should render the results table, got: %q", plainOut)
	}

	layeredOut := captureStdout(t, func() {
		r := render.NewRenderer(output.ModePlain)
		printHealthMainOutput(r, output.ModePlain, results, insights, nil, true, false)
	})
	if layeredOut == "" {
		t.Error("layered mode should render a layered report")
	}
}

// TestRunWatchSingleIteration drives runWatch with a context that is already
// cancelled, so run() executes exactly once (a real, terse-equivalent health
// collection) before the select loop observes ctx.Done() and returns — this
// covers runWatch's body without ever blocking on the ticker.
func TestRunWatchSingleIteration(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping real-collector run in short mode")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	ctrCtx := platform.ContainerContext{}
	cloudEnv := platform.EnvUnknown
	profile := platform.Profile{}

	done := make(chan error, 1)
	go func() {
		done <- runWatch(ctx, time.Hour, ctrCtx, cloudEnv, profile, output.ModePlain)
	}()
	select {
	case err := <-done:
		if err != nil {
			t.Errorf("runWatch: %v", err)
		}
	case <-time.After(30 * time.Second):
		t.Fatal("runWatch did not return after its context was cancelled")
	}
}

// newBareHealthCmd builds a bare cobra.Command with the flags runHealth reads.
func newBareHealthCmd() *cobra.Command {
	c := &cobra.Command{}
	f := c.Flags()
	f.Bool("plain", true, "")
	f.Bool("json", false, "")
	f.Bool("yaml", false, "")
	f.Bool("blob", false, "")
	f.Bool("nagios", false, "")
	f.Bool("prometheus", false, "")
	f.Bool("watch", false, "")
	f.Duration("watch-interval", time.Minute, "")
	f.Bool("debug", false, "")
	f.Bool("terse", true, "")
	f.Bool("story", false, "")
	f.Bool("packages", false, "")
	f.Bool("gpu", false, "")
	f.Bool("tls", false, "")
	f.Bool("deep", false, "")
	f.Bool("firmware", false, "")
	f.Bool("cve", false, "")
	f.Bool("report", false, "")
	f.Bool("report-html", false, "")
	f.String("policy", "", "")
	f.Bool("weekly", false, "")
	f.Bool("since-deploy", false, "")
	f.String("post-mortem", "", "")
	f.Bool("layered", false, "")
	f.Bool("diff", false, "")
	f.Bool("explain", false, "")
	f.Bool("fix", false, "")
	f.Bool("qr", false, "")
	c.SetContext(context.Background())
	return c
}

// TestRunHealthBadPolicyPath covers runHealth's early, safe-to-reach error
// return: an unloadable --policy file makes it return before any collector
// runs and long before the exit-code tail (see file-level comment for why
// the tail is out of scope here).
func TestRunHealthBadPolicyPath(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	c := newBareHealthCmd()
	_ = c.Flags().Set("policy", filepath.Join(t.TempDir(), "no-such-policy.yaml"))
	captureStderr(t, func() {
		err := runHealth(c, nil)
		if err == nil {
			t.Fatal("an unloadable --policy file should make runHealth return an error")
		}
	})
}

// TestRunHealthStoryWithHistory covers runHealth's --story fast path: with
// >=2 saved history snapshots it renders the story and returns nil, never
// reaching the live-collector / exit-code tail.
func TestRunHealthStoryWithHistory(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	hostname, _ := os.Hostname()
	dir := filepath.Join(home, ".dsd", "baselines")
	if err := os.MkdirAll(dir, 0o750); err != nil {
		t.Fatal(err)
	}
	for i, ts := range []string{"20200101-000000", "20200102-000000"} {
		snap := baseline.Snapshot{Hostname: hostname, Timestamp: time.Now().AddDate(0, 0, -2+i)}
		data, err := json.Marshal(snap)
		if err != nil {
			t.Fatal(err)
		}
		path := filepath.Join(dir, fmt.Sprintf("%s-%s.json", hostname, ts))
		if err := os.WriteFile(path, data, 0o600); err != nil {
			t.Fatal(err)
		}
	}

	c := newBareHealthCmd()
	_ = c.Flags().Set("story", "true")
	out := captureStdout(t, func() {
		if err := runHealth(c, nil); err != nil {
			t.Fatalf("runHealth --story: %v", err)
		}
	})
	if out == "" {
		t.Error("--story with sufficient history should render a story and return before any live collection")
	}
}
