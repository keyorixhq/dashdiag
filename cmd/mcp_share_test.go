package cmd

// mcp_share_test.go — unit tests for the dsd_share MCP tool, mirroring
// mcp_test.go's toolReplay/toolCapture coverage: error paths reachable when a
// caller invokes the handler directly (bypassing the MCP SDK's schema check),
// with emphasis on from_path's CWD confinement (safeBundlePath) — the same
// threat model as out_path/bundle_path (docs/THREAT_MODEL.md's "MCP
// out_path" section): from_path is not necessarily operator-typed in agentic
// use.

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

func TestToolShare_UnknownFormat(t *testing.T) {
	t.Parallel()
	_, _, err := toolShare(context.Background(), &mcp.CallToolRequest{}, mcpShareInput{Format: "pdf"})
	if err == nil {
		t.Fatal("expected error for unknown format, got nil")
	}
	if !strings.Contains(err.Error(), "dsd_share") || !strings.Contains(err.Error(), "pdf") {
		t.Errorf("unexpected error message: %q", err.Error())
	}
}

// TestToolShare_FromPathRejectsOutsideCWD is the confinement regression: an
// LLM-supplied from_path pointing outside the MCP server's CWD must be
// rejected before any file is touched — the same guarantee
// dsd_replay/dsd_diff's bundle_path/baseline_path/current_path already give.
func TestToolShare_FromPathRejectsOutsideCWD(t *testing.T) {
	mcpAllowAbsolutePaths = false
	cwd, err := os.Getwd()
	if err != nil {
		t.Fatalf("Getwd: %v", err)
	}
	outside := filepath.Join(filepath.Dir(cwd), "elsewhere", "escaped-snapshot.json")

	_, _, toolErr := toolShare(context.Background(), &mcp.CallToolRequest{}, mcpShareInput{FromPath: outside})
	if toolErr == nil {
		t.Fatal("expected an error for a from_path outside CWD, got nil")
	}
	if !strings.Contains(toolErr.Error(), "dsd_share") || !strings.Contains(toolErr.Error(), "from_path") {
		t.Errorf("unexpected error message: %q", toolErr.Error())
	}
	if !strings.Contains(toolErr.Error(), "current working directory") {
		t.Errorf("expected the CWD-confinement message, got: %q", toolErr.Error())
	}
}

// TestToolShare_FromPathNonexistent verifies a from_path that resolves
// inside CWD (so it passes confinement) but names no real file surfaces a
// normal load error, not a panic.
func TestToolShare_FromPathNonexistent(t *testing.T) {
	t.Parallel()
	dir := tempDirUnderCWD(t)
	_, _, err := toolShare(context.Background(), &mcp.CallToolRequest{},
		mcpShareInput{FromPath: filepath.Join(dir, "nonexistent-snapshot.json")})
	if err == nil {
		t.Fatal("expected an error for a nonexistent from_path, got nil")
	}
	if strings.Contains(err.Error(), "current working directory") {
		t.Errorf("a path inside CWD should not fail confinement, got: %q", err.Error())
	}
}
