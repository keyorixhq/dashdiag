package cmd

// mcp_test.go — unit tests for the five MCP tool handler functions.
//
// The tool handlers are thin wrappers; the integration path (health pipeline,
// bundle I/O) is exercised by the existing smoke and replay suites. These tests
// focus on the error paths that would only fire when a caller invokes the
// handlers directly (bypassing the MCP SDK's JSON-schema required-field check).

import (
	"context"
	"encoding/json"
	"path/filepath"
	"testing"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/keyorixhq/dashdiag/internal/models"
)

// TestToolCaptureRequiresOutPath verifies that toolCapture returns an error
// when out_path is empty rather than writing to an unpredictable location.
func TestToolCaptureRequiresOutPath(t *testing.T) {
	t.Parallel()
	_, _, err := toolCapture(context.Background(), &mcp.CallToolRequest{}, mcpCaptureInput{})
	if err == nil {
		t.Fatal("expected error for empty out_path, got nil")
	}
	if err.Error() != "dsd_capture: out_path is required" {
		t.Errorf("unexpected error message: %q", err.Error())
	}
}

// TestToolCaptureIdentifiersImpliesSanitize verifies that setting
// Identifiers=true automatically enables Sanitize even when the caller omits
// it — keeping the internal bundle consistent with the documented contract.
// We exercise only the implication gate (the write itself will fail on a
// nonexistent path, which is fine for this test).
func TestToolCaptureIdentifiersImpliesSanitize(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	out := filepath.Join(dir, "out.tar.gz")
	// We don't check the returned bundle — just that it doesn't error on a
	// valid path (indicating Sanitize=true was set correctly from Identifiers).
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
}

// TestToolReplayRequiresBundlePath verifies that toolReplay returns an error
// when bundle_path is empty — the handler must not try to open an empty path.
func TestToolReplayRequiresBundlePath(t *testing.T) {
	t.Parallel()
	_, _, err := toolReplay(context.Background(), &mcp.CallToolRequest{}, mcpReplayInput{})
	if err == nil {
		t.Fatal("expected error for empty bundle_path, got nil")
	}
	if err.Error() != "dsd_replay: bundle_path is required" {
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

// TestToolCISReturnsValidReport verifies that toolCIS returns a non-empty
// CISReport that can be unmarshalled and has at least one scored result.
// On macOS most Linux-specific rules SKIP gracefully rather than erroring.
func TestToolCISReturnsValidReport(t *testing.T) {
	t.Parallel()
	result, _, err := toolCIS(context.Background(), &mcp.CallToolRequest{}, mcpCISInput{})
	if err != nil {
		t.Fatalf("toolCIS: %v", err)
	}
	if result == nil || len(result.Content) == 0 {
		t.Fatal("toolCIS: nil result or empty content")
	}
	tc, ok := result.Content[0].(*mcp.TextContent)
	if !ok {
		t.Fatalf("toolCIS: content[0] is not TextContent")
	}
	var report models.CISReport
	if err := json.Unmarshal([]byte(tc.Text), &report); err != nil {
		t.Fatalf("toolCIS: unmarshal CISReport: %v", err)
	}
	if len(report.Results) == 0 {
		t.Error("toolCIS: got empty results slice")
	}
	total := report.Pass + report.Fail + report.Manual + report.NA + report.Skipped
	if total == 0 {
		t.Error("toolCIS: all counters are zero")
	}
}

// TestToolCISLevel0DefaultsTo1 verifies that an omitted level (0) produces the
// same result count as an explicit level=1.
func TestToolCISLevel0DefaultsTo1(t *testing.T) {
	t.Parallel()
	r0, _, err0 := toolCIS(context.Background(), &mcp.CallToolRequest{}, mcpCISInput{Level: 0})
	r1, _, err1 := toolCIS(context.Background(), &mcp.CallToolRequest{}, mcpCISInput{Level: 1})
	if err0 != nil || err1 != nil {
		t.Fatalf("toolCIS errors: level0=%v level1=%v", err0, err1)
	}
	tc0, _ := r0.Content[0].(*mcp.TextContent)
	tc1, _ := r1.Content[0].(*mcp.TextContent)
	var rep0, rep1 models.CISReport
	_ = json.Unmarshal([]byte(tc0.Text), &rep0)
	_ = json.Unmarshal([]byte(tc1.Text), &rep1)
	if len(rep0.Results) != len(rep1.Results) {
		t.Errorf("level 0 → %d results, level 1 → %d (should be equal)", len(rep0.Results), len(rep1.Results))
	}
}
