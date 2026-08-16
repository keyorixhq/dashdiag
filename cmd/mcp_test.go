package cmd

// mcp_test.go — unit tests for the four MCP tool handler functions.
//
// The tool handlers are thin wrappers; the integration path (health pipeline,
// bundle I/O) is exercised by the existing smoke and replay suites. These tests
// focus on the error paths that would only fire when a caller invokes the
// handlers directly (bypassing the MCP SDK's JSON-schema required-field check).

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/keyorixhq/dashdiag/internal/analysis"
	"github.com/keyorixhq/dashdiag/internal/baseline"
	"github.com/keyorixhq/dashdiag/internal/models"
	"github.com/keyorixhq/dashdiag/internal/output"
	"github.com/keyorixhq/dashdiag/internal/platform"
	"github.com/keyorixhq/dashdiag/internal/runner"
)

// ctxProbeKey is a distinctive, unexported context key used only by the
// ForwardsCallerContext regression tests below, so a value stashed on the
// caller's context can be told apart from anything else that might be on it.
type ctxProbeKey struct{}

// TestToolCaptureRequiresOutPath verifies that toolCapture returns an error
// when out_path is empty rather than writing to an unpredictable location.
func TestToolCaptureRequiresOutPath(t *testing.T) {
	t.Parallel()
	_, _, err := toolCapture(context.Background(), &mcp.CallToolRequest{}, mcpCaptureInput{})
	if err == nil {
		t.Fatal("expected error for empty out_path, got nil")
	}
	if !strings.Contains(err.Error(), "dsd_capture") || !strings.Contains(err.Error(), "out_path") {
		t.Errorf("unexpected error message: %q", err.Error())
	}
}

// TestToolCaptureIdentifiersImpliesSanitize verifies that setting
// Identifiers=true automatically enables Sanitize even when the caller omits
// it — keeping the internal bundle consistent with the documented contract —
// and that toolCapture's own JSON response doesn't echo the real hostname
// (redaction-primitives-05: the bundle FILE correctly showed the placeholder,
// but a caller that logs/forwards the tool result, a common agent pattern,
// got the real hostname anyway via the "host" response field). Both
// assertions share a single toolCapture call (which runs the full live
// health-collection pipeline) rather than two, since a second parallel call
// serialized behind mcpPipelineMu pushed the cmd package's test suite over
// its 180s CI budget.
func TestToolCaptureIdentifiersImpliesSanitize(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	out := filepath.Join(dir, "out.tar.gz")

	realHost, hostErr := os.Hostname()

	_, result, err := toolCapture(context.Background(), &mcp.CallToolRequest{},
		mcpCaptureInput{OutPath: out, Identifiers: true, Sanitize: false})
	if err != nil {
		t.Fatalf("toolCapture with Identifiers: %v", err)
	}
	if result.BundlePath != out {
		t.Errorf("bundle_path = %q, want %q", result.BundlePath, out)
	}
	if result.Bytes <= 0 {
		t.Errorf("expected positive bundle size, got %d", result.Bytes)
	}
	if hostErr == nil && realHost != "" && result.Host == realHost {
		t.Errorf("toolCapture response disclosed the real hostname %q despite Identifiers:true", realHost)
	}
	// sanitize-bundle-03: the MCP response must disclose sanitize state
	// structurally, the same way dsd capture --raw's stderr warning does —
	// not just write an unlabeled bundle_path.
	if !result.Sanitized {
		t.Errorf("Sanitized should be true when Identifiers implies Sanitize, got false")
	}
	if !strings.Contains(result.Note, "Sanitized (best-effort)") {
		t.Errorf("Note should disclose the sanitize state, got: %q", result.Note)
	}
	if !strings.Contains(result.Note, "Identifiers redacted") {
		t.Errorf("Note should mention identifier redaction when Identifiers:true, got: %q", result.Note)
	}
}

// TestToolCaptureUnsanitizedDisclosesNote guards sanitize-bundle-03's other
// branch: a caller that leaves Sanitize/Identifiers both false (the tool's
// documented default) must get an explicit "this is unredacted" signal in
// the response, the same as dsd capture --raw's stderr warning gives a
// human — not a bundle_path with no indication the contents are raw.
func TestToolCaptureUnsanitizedDisclosesNote(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	out := filepath.Join(dir, "out.tar.gz")

	_, result, err := toolCapture(context.Background(), &mcp.CallToolRequest{},
		mcpCaptureInput{OutPath: out})
	if err != nil {
		t.Fatalf("toolCapture: %v", err)
	}
	if result.Sanitized {
		t.Error("Sanitized should be false when the caller didn't set Sanitize/Identifiers")
	}
	if !strings.Contains(result.Note, "unredacted") {
		t.Errorf("Note should disclose the bundle is unredacted, got: %q", result.Note)
	}
	if !strings.Contains(result.Note, "--sanitize") {
		t.Errorf("Note should point the caller at --sanitize, got: %q", result.Note)
	}
}

// TestRedactMCPJSON guards sanitize-bundle-01: toolHealth/toolReplay returned
// their rendered JSON verbatim over MCP with no redaction path at all, even
// though checks[].raw is documented out-of-contract and may carry a
// collector's verbatim raw data. Exercises redactMCPJSON directly (the exact
// helper toolHealth/toolReplay call) on compact JSON — the shape where a
// naive byte-level regex pass against already-serialized JSON would corrupt
// structure, which is why redaction happens on the decoded value instead.
func TestRedactMCPJSON(t *testing.T) {
	t.Parallel()
	in := []byte(`{"checks":[{"name":"env","status":"OK","raw":{"line":"token=abc123secretvalue"}}]}`)
	out := redactMCPJSON(in)
	if strings.Contains(string(out), "abc123secretvalue") {
		t.Errorf("secret survived redactMCPJSON: %s", out)
	}
	if !json.Valid(out) {
		t.Fatalf("redactMCPJSON produced invalid JSON: %s", out)
	}
	if !strings.Contains(string(out), `"status":"OK"`) {
		t.Errorf("non-secret field corrupted: %s", out)
	}
}

// TestToolHealth_ForwardsCallerContext is the regression test for
// cmd-09-03: toolHealth used to discard its request-scoped ctx parameter and
// build a fresh context.Background() instead, so a JSON-RPC caller that
// cancelled or timed out the call could not bound the underlying health
// pipeline. runHealthOnceFn is swapped for a stub that just records the ctx
// it receives; a value stashed on the ctx passed into toolHealth must survive
// into the stub, which only holds if toolHealth forwards the real ctx.
func TestToolHealth_ForwardsCallerContext(t *testing.T) {
	// No t.Parallel(): swaps the package-global runHealthOnceFn seam.
	prev := runHealthOnceFn
	t.Cleanup(func() { runHealthOnceFn = prev })

	var gotCtx context.Context
	runHealthOnceFn = func(ctx context.Context, _ platform.ContainerContext, _ platform.CloudEnvironment,
		_ platform.Profile, _ output.OutputMode, _ healthRunOpts, _ *analysis.PolicyFile,
	) ([]runner.Result, []models.Insight, *baseline.Snapshot, time.Duration) {
		gotCtx = ctx
		return nil, nil, nil, 0
	}

	callerCtx := context.WithValue(context.Background(), ctxProbeKey{}, "toolHealth-caller")
	if _, _, err := toolHealth(callerCtx, &mcp.CallToolRequest{}, mcpHealthInput{}); err != nil {
		t.Fatalf("toolHealth: %v", err)
	}

	if gotCtx == nil {
		t.Fatal("runHealthOnceFn was never called")
	}
	if got := gotCtx.Value(ctxProbeKey{}); got != "toolHealth-caller" {
		t.Errorf("runHealthOnce received a ctx that lost the caller's value (got %v) — "+
			"toolHealth must forward the request ctx, not substitute context.Background()", got)
	}
}

// TestToolCapture_ForwardsCallerContext is the same regression as
// TestToolHealth_ForwardsCallerContext, for toolCapture's identical bug.
func TestToolCapture_ForwardsCallerContext(t *testing.T) {
	// No t.Parallel(): swaps the package-global runHealthOnceFn seam.
	prev := runHealthOnceFn
	t.Cleanup(func() { runHealthOnceFn = prev })

	var gotCtx context.Context
	runHealthOnceFn = func(ctx context.Context, _ platform.ContainerContext, _ platform.CloudEnvironment,
		_ platform.Profile, _ output.OutputMode, _ healthRunOpts, _ *analysis.PolicyFile,
	) ([]runner.Result, []models.Insight, *baseline.Snapshot, time.Duration) {
		gotCtx = ctx
		return nil, nil, nil, 0
	}

	dir := t.TempDir()
	out := filepath.Join(dir, "out.tar.gz")
	callerCtx := context.WithValue(context.Background(), ctxProbeKey{}, "toolCapture-caller")
	if _, _, err := toolCapture(callerCtx, &mcp.CallToolRequest{}, mcpCaptureInput{OutPath: out}); err != nil {
		t.Fatalf("toolCapture: %v", err)
	}

	if gotCtx == nil {
		t.Fatal("runHealthOnceFn was never called")
	}
	if got := gotCtx.Value(ctxProbeKey{}); got != "toolCapture-caller" {
		t.Errorf("runHealthOnce received a ctx that lost the caller's value (got %v) — "+
			"toolCapture must forward the request ctx, not substitute context.Background()", got)
	}
}

// TestToolReplayRequiresBundlePath verifies that toolReplay returns an error
// when bundle_path is empty — the handler must not try to open an empty path.
func TestToolReplayRequiresBundlePath(t *testing.T) {
	t.Parallel()
	_, _, err := toolReplay(context.Background(), &mcp.CallToolRequest{}, mcpReplayInput{})
	if err == nil {
		t.Fatal("expected error for empty bundle_path, got nil")
	}
	if !strings.Contains(err.Error(), "dsd_replay") || !strings.Contains(err.Error(), "bundle_path") {
		t.Errorf("unexpected error message: %q", err.Error())
	}
}

// TestToolReplayNonexistentBundle verifies that toolReplay returns a loadBundle
// error (not a panic or nil) when the named bundle does not exist on disk.
func TestToolReplayNonexistentBundle(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	_, _, err := toolReplay(context.Background(), &mcp.CallToolRequest{},
		mcpReplayInput{BundlePath: filepath.Join(dir, "nonexistent.tar.gz")})
	if err == nil {
		t.Fatal("expected error for nonexistent bundle, got nil")
	}
}

// TestToolDiffRequiresBothPaths verifies that toolDiff returns an error when
// either baseline_path or current_path is empty.
func TestToolDiffRequiresBothPaths(t *testing.T) {
	t.Parallel()
	cases := []mcpDiffInput{
		{},
		{BaselinePath: "/a", CurrentPath: ""},
		{BaselinePath: "", CurrentPath: "/b"},
	}
	for _, in := range cases {
		_, _, err := toolDiff(context.Background(), &mcp.CallToolRequest{}, in)
		if err == nil {
			t.Errorf("expected error for input %+v, got nil", in)
		}
	}
}

// TestToolDiffNonexistentBundle verifies that toolDiff returns a loadBundle
// error when the baseline bundle does not exist.
func TestToolDiffNonexistentBundle(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	_, _, err := toolDiff(context.Background(), &mcp.CallToolRequest{}, mcpDiffInput{
		BaselinePath: filepath.Join(dir, "a.tar.gz"),
		CurrentPath:  filepath.Join(dir, "b.tar.gz"),
	})
	if err == nil {
		t.Fatal("expected error for nonexistent bundles, got nil")
	}
}

// TestToolDiffRedactsSecretShapedMessage is the regression test for the gap
// TestEveryMCPToolHandlerRedactsSecrets guards mechanically: toolDiff's
// response is built from baseline.ComputeDiff([]DiffEntry).Before/After,
// which is Status+" "+Value, and Value is copied from the worst-ranked
// matching insight's Message (see BuildSnapshot) — the same free-text field
// that already gets redacted when it surfaces via insights[].message in
// dsd_health/dsd_replay. A real-world instance: heuristics_web.go's
// webConfigVerdict concatenates a web server's raw config-test stderr
// straight into a CRIT Message with no secret-pattern filtering.
//
// Exercises the exact composition toolDiff itself performs on the response
// — baseline.ComputeDiff -> json.Marshal -> redactMCPJSON — against
// hand-built Snapshots rather than a second full live-collector bundle pair
// (this file's TestToolCaptureIdentifiersImpliesSanitize's own comment notes
// why a second full pipeline run isn't worth the CI time here: toolDiff's
// own file-loading/replay plumbing is already covered by
// TestToolDiffNonexistentBundle/TestToolDiffRequiresBothPaths, and
// controlling exactly which heuristic fires a secret-shaped Message through
// a real collector run would need its own dedicated fixture anyway). This
// is the load-bearing question — does a secret-shaped Value actually get
// redacted by the time it reaches the wire — not the bundle-file plumbing
// around it.
func TestToolDiffRedactsSecretShapedMessage(t *testing.T) {
	t.Parallel()
	before := &baseline.Snapshot{Checks: []baseline.CheckResult{
		{Name: "Web", Status: "OK", Value: "config valid"},
	}}
	after := &baseline.Snapshot{Checks: []baseline.CheckResult{
		{Name: "Web", Status: "CRIT", Value: `nginx config INVALID: auth_basic_user_file password=hunter2secretvalue`},
	}}

	entries := baseline.ComputeDiff(before, after)
	data, err := json.Marshal(entries)
	if err != nil {
		t.Fatalf("marshalling diff: %v", err)
	}
	got := redactMCPJSON(data)

	if strings.Contains(string(got), "hunter2secretvalue") {
		t.Errorf("secret-shaped Value survived redactMCPJSON in a diff entry: %s", got)
	}
	if !json.Valid(got) {
		t.Fatalf("redactMCPJSON produced invalid JSON: %s", got)
	}
	if !strings.Contains(string(got), `"Name":"Web"`) {
		t.Errorf("non-secret field corrupted: %s", got)
	}
	if !strings.Contains(string(got), "CRIT") {
		t.Errorf("status should survive redaction: %s", got)
	}
}

// TestMCPPipelineMu_SerializesToolCapture is the regression guard for the
// collectors.activeSource cross-contamination race: the MCP SDK runs
// concurrent tool calls (jsonrpc2.Async for every non-initialize request),
// and toolCapture swaps the process-global active Source for its full
// multi-second collector run — without a lock, a concurrent toolHealth/
// toolReplay/toolDiff call could read through (or tee into) this call's
// Recorder mid-flight. Proves the wiring, not just that sync.Mutex itself
// works: while a real toolCapture run (a full collector sweep, ~1-2s) is
// in flight in another goroutine, mcpPipelineMu.TryLock() from this
// goroutine must fail — and must succeed only after toolCapture returns.
//
// Not t.Parallel(): this test's correctness depends on being the only thing
// contending for mcpPipelineMu at the moment it TryLocks, which a sibling
// parallel test also calling a tool handler would defeat.
func TestMCPPipelineMu_SerializesToolCapture(t *testing.T) {
	dir := t.TempDir()
	out := filepath.Join(dir, "out.tar.gz")

	done := make(chan struct{})
	go func() {
		defer close(done)
		_, _, err := toolCapture(context.Background(), &mcp.CallToolRequest{}, mcpCaptureInput{OutPath: out})
		if err != nil {
			t.Errorf("toolCapture: %v", err)
		}
	}()

	// Give the goroutine time to acquire mcpPipelineMu and start its collector
	// run — toolCapture's own real run takes over a second (see
	// TestToolCaptureIdentifiersImpliesSanitize), so this is a generous margin,
	// not a tight race.
	time.Sleep(50 * time.Millisecond)

	select {
	case <-done:
		t.Fatal("toolCapture finished before the lock-contention check could run — test is racing the collector, not the lock")
	default:
	}

	if mcpPipelineMu.TryLock() {
		mcpPipelineMu.Unlock()
		t.Fatal("mcpPipelineMu was NOT held while toolCapture was in flight — concurrent calls are not serialized")
	}

	<-done

	if !mcpPipelineMu.TryLock() {
		t.Fatal("mcpPipelineMu still held after toolCapture returned — lock leaked")
	}
	mcpPipelineMu.Unlock()
}
