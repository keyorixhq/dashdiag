package cmd

// mcp_framing_repro_test.go — reproducer for NET1-F6: go-sdk's stdio/IO
// transport decodes the input with a streaming json.Decoder
// (mcp/transport.go newIOConnLimited) instead of splitting on newlines, so a
// truncated frame does not fail on its own line: it absorbs the following
// frame(s), and the request in them is never answered. The MCP stdio
// transport spec defines messages as newline-delimited.
//
// Oracle: after a one-line frame that is not complete JSON, a following
// valid ping is answered (or the session is closed) within the deadline.
// Red half gated by DSD_NET1_REPRO=1 (fails on go-sdk v1.8.0); the green half
// shows the same oracle passes when the bad line is complete-but-invalid.
//
// What this does NOT verify: whether a merged frame can form a different,
// valid request (plausible: `{"jsonrpc":"2.0","id":1,"method":"tools/call",
// "params":` + newline + `{...}}` — not asserted here); that any real MCP
// client ever emits a truncated line (the client is trusted; the LLM cannot
// produce one).

import (
	"encoding/json"
	"fmt"
	"os"
	"testing"
	"time"
)

func mcpPingAfter(t *testing.T, badLine string) bool {
	t.Helper()
	rec := &mcpFuzzRecorder{}
	s := startMCPFuzzSession(t, rec)
	defer s.close()
	s.closeOK = true
	seen := map[string]int{}
	s.send(t, mcpFuzzInit)
	_, _ = s.awaitID(t, "dsdfz-init", seen)
	s.send(t, mcpFuzzInitialized)
	if !s.send(t, badLine) || !s.send(t, mcpFuzzPing) {
		return true // session closed: bounded, not a hang
	}
	return s.resolvedWithin("dsdfz-ping")
}

// resolvedWithin reports whether, within mcpFuzzDeadline, a response with id
// want arrived or the server closed its output; false only on a hang.
func (s *mcpFuzzSession) resolvedWithin(want string) bool {
	deadline := time.After(mcpFuzzDeadline)
	for {
		select {
		case line, ok := <-s.lines:
			if !ok {
				return true
			}
			var msg map[string]any
			if json.Unmarshal([]byte(line), &msg) == nil && fmt.Sprint(msg["id"]) == want {
				return true
			}
		case <-deadline:
			return false
		}
	}
}

func TestReproMCPTruncatedFrameSwallowsNext(t *testing.T) {
	if os.Getenv("DSD_NET1_REPRO") != "1" {
		t.Skip("red half of the NET1-F6 proof; set DSD_NET1_REPRO=1 (fails on go-sdk v1.8.0)")
	}
	if !mcpPingAfter(t, `{"":`) {
		t.Errorf("ping after the one-line truncated frame {\"\": was never answered (frame merged with the next line)")
	}
}

func TestReproMCPTruncatedFrameSwallowsNext_CompleteGreen(t *testing.T) {
	if !mcpPingAfter(t, `{"":1}`) {
		t.Fatal("ping after a complete frame was not answered and the session did not close")
	}
}
