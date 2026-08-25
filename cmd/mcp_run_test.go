package cmd

// mcp_run_test.go — covers runMCP's own body (previously untested: the
// mcp.AddTool wiring and srv.Run call are only exercised statically by
// mcp_governance_test.go's AST walk, never actually executed). Feeding
// stdin an immediate EOF makes the StdioTransport's read loop end right
// away, so srv.Run returns a clean nil rather than blocking — same
// stdin-swap idiom as withHookStdin in hook_run_test.go.

import (
	"os"
	"testing"
	"time"
)

// TestRunMCP_CleanEOFShutdown redirects stdin to a pipe that is closed
// immediately, so the MCP server's stdio transport observes EOF on its very
// first read and srv.Run returns without ever handling a request. This
// exercises runMCP's tool-registration body end to end without needing a
// real MCP client.
func TestRunMCP_CleanEOFShutdown(t *testing.T) {
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("Pipe: %v", err)
	}
	old := os.Stdin
	os.Stdin = r
	t.Cleanup(func() { os.Stdin = old })
	if err := w.Close(); err != nil {
		t.Fatalf("closing pipe write end: %v", err)
	}

	done := make(chan error, 1)
	go func() { done <- runMCP(nil, nil) }()

	select {
	case err := <-done:
		if err != nil {
			t.Errorf("runMCP: %v, want nil on a clean EOF shutdown", err)
		}
	case <-time.After(30 * time.Second):
		t.Fatal("runMCP did not return after stdin reached EOF")
	}
}
