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
