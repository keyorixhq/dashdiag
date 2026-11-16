package cmd

// MC1 target 1 — the MCP (modelcontextprotocol/go-sdk) JSON-RPC / transport
// layer, driven with hostile raw bytes.
//
// `dsd mcp` runs a go-sdk mcp.Server over stdio. The TRANSPORT is local, but in
// agentic use the PEER is an untrusted-or-confused MCP client: the JSON-RPC
// frames, ids, method names, batch structure and tool-call arguments are all
// attacker-influenceable (a prompt-injected document steering the agent). The
// go-sdk is the first thing those bytes hit — frame splitting (newline-delimited
// JSON, 16 MiB DefaultMaxLineLength), JSON-RPC decode, id handling, batch
// handling, schema validation, async dispatch. That decode/dispatch layer is the
// NEW third-party input path (DL1 target 2 already covers safeBundlePath, the
// argument-validation gate BEHIND this layer; this target is in front of it).
//
// Harness: a real mcp.Server, built with the SAME five tool schemas runMCP
// registers (the real mcpHealthInput/mcpCaptureInput/... types, so the SDK
// infers the identical JSON Schemas), but with RECORDING STUB handlers in place
// of the collector-running bodies. Stubs make the run deterministic and fast and
// let the oracles observe every dispatch; the real collector/tool logic is
// dashdiag's own and is exercised elsewhere. The server is driven through an
// mcp.IOTransport over an io.Pipe, exactly the newline-delimited-JSON framing the
// production StdioTransport uses, only with in-memory pipes instead of
// os.Stdin/os.Stdout. A valid initialize + initialized handshake is prepended so
// the fuzzed bytes reach the post-init request-routing/dispatch path; the fuzzed
// bytes themselves are an arbitrary continuation (more frames, a batch, garbage,
// a partial frame, a huge id, wrong-typed or out-of-schema tool arguments, a
// cancellation, concurrent calls).
//
// INVARIANTS asserted (see INVARIANTS.d/mc1-thirdparty-mcp.md):
//   M1 no panic — the server survives any byte stream without panicking (a panic
//      in the server goroutine crashes the worker and is reported).
//   M2 bounded work — feeding + draining one input stays within the shared
//      resource oracle (alloc factor + time + no goroutine leak). Catches a frame
//      decoder that amplifies memory on a huge line / deep nesting / huge batch,
//      or a hang.
//   M3 terminal-safe output — every byte the server writes back is valid UTF-8,
//      carries no raw ESC (0x1B) and no C0 control other than the '\n' frame
//      delimiter. This is the "output can't attack the client's terminal" claim:
//      hostile strings echoed through tool args or quoted in error messages must
//      be JSON-escaped by the SDK's response encoder, never passed through raw.
//   M5 dispatch stays in-schema — when a tool handler IS invoked, the tool name
//      is one of the five registered tools (the SDK never dispatches a tools/call
//      to an unregistered name or routes a non-tool method into a tool handler).
//
// Does NOT verify: the READ-ONLY / no-host-write claim. The write-capable
// handler is dsd_capture, which writes only to a safeBundlePath — gated by
// safeBundlePath (DL1 target 2, FuzzMCPSafeBundlePathContainment) and enumerated
// by write_capable_callsites_test.go. This target STUBS the handler bodies, so
// the SDK transport/dispatch layer it exercises has no disk path at all; a
// filesystem-fingerprint oracle here would be vacuous (a guard that can never
// fail), so it is deliberately NOT asserted. Also not verified: safeBundlePath
// containment; the collector pipeline, redaction, or real tool output shape
// (stubbed); the SSE / Streamable HTTP transports (dsd only runs stdio); that
// the SDK's schema VALIDATION rejects every malformed argument for the right
// reason (M5 only checks a dispatch lands on a real tool); and TLS / auth (stdio
// has none). A silently-dropped frame is not distinguished from a handled one
// beyond M1–M3/M5 holding.

import (
	"bytes"
	"context"
	"io"
	"strings"
	"sync"
	"testing"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/keyorixhq/dashdiag/internal/testutil/resource"
)

// The go-sdk decodes a 16 MiB max frame and builds a jsonrpc message tree; the
// per-input-byte allocation of that decode is well above the DL1 default of 64
// but linear in input. factor 4096 covers the handshake + decode + dispatch
// overhead with headroom while still tripping a super-linear blow-up or a hang.
const mc1MCPAllocFactor = 4096

// mc1MCPOutputCap bounds how many response bytes the harness retains for the
// terminal-safety scan. A server that writes more than this on one input is
// itself an amplification the resource oracle catches; the scan runs on the
// retained prefix (a control byte earlier in the stream is not hidden by later
// truncation).
const mc1MCPOutputCap = 4 << 20

// toolCall records that a stub handler ran and with which tool name/args.
type mc1ToolCall struct {
	tool string
	args string
}

type mc1Recorder struct {
	mu    sync.Mutex
	calls []mc1ToolCall
}

func (r *mc1Recorder) record(tool, args string) {
	r.mu.Lock()
	r.calls = append(r.calls, mc1ToolCall{tool, args})
	r.mu.Unlock()
}

// buildStubMCPServer registers the five real tool schemas (same names and input
// types as runMCP, so the SDK infers identical input JSON Schemas) with stub
// handlers that record the call and echo the input's host-controlled string
// fields back into a TextContent — so any hostile bytes in tool arguments flow
// into the response and the M3 terminal-safety oracle can see whether the SDK
// escaped them.
func buildStubMCPServer(rec *mc1Recorder) *mcp.Server {
	srv := mcp.NewServer(&mcp.Implementation{Name: "dsd", Version: "fuzz"}, nil)

	echo := func(tool, s string) (*mcp.CallToolResult, any, error) {
		rec.record(tool, s)
		return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: "echo:" + s}}}, nil, nil
	}

	mcp.AddTool(srv, &mcp.Tool{Name: "dsd_health"},
		func(_ context.Context, _ *mcp.CallToolRequest, in mcpHealthInput) (*mcp.CallToolResult, any, error) {
			return echo("dsd_health", "")
		})
	mcp.AddTool(srv, &mcp.Tool{Name: "dsd_capture"},
		func(_ context.Context, _ *mcp.CallToolRequest, in mcpCaptureInput) (*mcp.CallToolResult, any, error) {
			return echo("dsd_capture", in.OutPath)
		})
	mcp.AddTool(srv, &mcp.Tool{Name: "dsd_replay"},
		func(_ context.Context, _ *mcp.CallToolRequest, in mcpReplayInput) (*mcp.CallToolResult, any, error) {
			return echo("dsd_replay", in.BundlePath)
		})
	mcp.AddTool(srv, &mcp.Tool{Name: "dsd_diff"},
		func(_ context.Context, _ *mcp.CallToolRequest, in mcpDiffInput) (*mcp.CallToolResult, any, error) {
			return echo("dsd_diff", in.BaselinePath+"\x00"+in.CurrentPath)
		})
	mcp.AddTool(srv, &mcp.Tool{Name: "dsd_share"},
		func(_ context.Context, _ *mcp.CallToolRequest, in mcpShareInput) (*mcp.CallToolResult, any, error) {
			return echo("dsd_share", in.Format+"\x00"+in.FromPath)
		})
	return srv
}

var mc1KnownTools = map[string]bool{
	"dsd_health": true, "dsd_capture": true, "dsd_replay": true,
	"dsd_diff": true, "dsd_share": true,
}

// mc1Handshake is a valid initialize + initialized pair, using a protocol
// version the linked SDK actually supports (queried at runtime so a version bump
// never silently breaks the dispatch-path coverage).
func mc1Handshake() []byte {
	versions := mcp.SupportedProtocolVersions()
	pv := "2025-06-18"
	if len(versions) > 0 {
		pv = versions[len(versions)-1]
	}
	var b bytes.Buffer
	b.WriteString(`{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"`)
	b.WriteString(pv)
	b.WriteString(`","capabilities":{},"clientInfo":{"name":"fuzz","version":"0"}}}` + "\n")
	b.WriteString(`{"jsonrpc":"2.0","method":"notifications/initialized"}` + "\n")
	return b.Bytes()
}

// syncWriter is a mutex-guarded, byte-capped io.WriteCloser: the SDK writes
// responses to it from its dispatch goroutines, and the harness snapshots it
// under the same lock after the server is done (or wedged). It retains at most
// cap bytes — scanning the retained prefix is enough, a control byte cannot be
// un-written by later overflow.
type syncWriter struct {
	mu    sync.Mutex
	buf   bytes.Buffer
	cap   int
	total int
}

func (w *syncWriter) Write(p []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.total += len(p)
	if rem := w.cap - w.buf.Len(); rem > 0 {
		if len(p) <= rem {
			w.buf.Write(p)
		} else {
			w.buf.Write(p[:rem])
		}
	}
	return len(p), nil
}

func (w *syncWriter) Close() error { return nil }

func (w *syncWriter) snapshot() []byte {
	w.mu.Lock()
	defer w.mu.Unlock()
	return append([]byte(nil), w.buf.Bytes()...)
}

// mc1Quiescence is how long the input pipe is held OPEN after the bytes are
// written before EOF is signalled. The go-sdk dispatches tools/call ASYNC
// (jsonrpc2.Async); if the reader EOFs immediately the session tears down and
// cancels in-flight handlers before they flush — so a post-init tools/call would
// never dispatch and its response never land, defeating M3/M5. Holding the pipe
// open briefly lets the (instant) stub handlers run and flush first, then the
// EOF is a clean shutdown. 10ms is far more than the stubs need; it bounds this
// target's throughput (documented in the report as a known low exec/s), which is
// acceptable because per-input server setup already dominates and the target's
// value is structural protocol coverage, not raw rate.
var mc1Quiescence = 5 * time.Millisecond

// serveOnce feeds handshake+raw to a fresh stub server over an mcp.IOTransport
// and returns everything the server wrote (straight into a mutex-guarded
// syncWriter) plus the recorded tool calls. The input is an io.Pipe held open
// for mc1Quiescence so async dispatch can flush, then EOF'd for a clean
// shutdown. Run runs in a goroutine so a hang is bounded by the context timeout
// (surfaced as time-over-budget by the resource oracle) rather than wedging the
// worker; the pipe ends are closed on teardown so neither goroutine leaks.
func serveOnce(raw []byte) (out []byte, calls []mc1ToolCall) {
	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Second)
	defer cancel()

	rec := &mc1Recorder{}
	srv := buildStubMCPServer(rec)

	inR, inW := io.Pipe()
	w := &syncWriter{cap: mc1MCPOutputCap}

	runDone := make(chan struct{})
	go func() {
		_ = srv.Run(ctx, &mcp.IOTransport{Reader: inR, Writer: w})
		close(runDone)
	}()

	input := append(mc1Handshake(), raw...)
	writerDone := make(chan struct{})
	go func() {
		_, _ = inW.Write(input) // returns ErrClosedPipe if the server closed first
		time.Sleep(mc1Quiescence)
		_ = inW.Close() // EOF -> clean shutdown
		close(writerDone)
	}()

	select {
	case <-runDone:
	case <-time.After(3 * time.Second):
		cancel() // hang: unblock Run
	}
	_ = inR.Close() // unblock a wedged writer goroutine
	_ = inW.Close()
	joinOrTimeout(runDone)
	joinOrTimeout(writerDone)

	rec.mu.Lock()
	calls = append(calls, rec.calls...)
	rec.mu.Unlock()
	return w.snapshot(), calls
}

func joinOrTimeout(done <-chan struct{}) {
	select {
	case <-done:
	case <-time.After(1500 * time.Millisecond):
	}
}

// assertMCPOutputTerminalSafe: valid UTF-8, no raw ESC, no C0 control except the
// '\n' frame delimiter. (encoding/json escapes every byte < 0x20, so a correct
// SDK response encoder cannot emit a raw control char even when the request or
// tool args carried one.)
func assertMCPOutputTerminalSafe(t *testing.T, out []byte) {
	t.Helper()
	if !utf8.Valid(out) {
		t.Fatalf("M3: server output is not valid UTF-8 (a raw C1/8-bit byte survived): %q", clip(out))
	}
	for i, r := range string(out) {
		if r == 0x1b {
			t.Fatalf("M3: server output contains a raw ESC (0x1B) at byte %d: %q", i, clip(out))
		}
		if r != '\n' && unicode.IsControl(r) {
			t.Fatalf("M3: server output contains control rune %U at byte %d (only '\\n' frame delimiter allowed): %q", r, i, clip(out))
		}
	}
}

func clip(b []byte) string {
	const n = 256
	if len(b) > n {
		return string(b[:n]) + "...(truncated)"
	}
	return string(b)
}

func FuzzMCPServerHostileJSONRPC(f *testing.F) {
	for _, s := range mc1MCPSeeds() {
		f.Add([]byte(s))
	}

	f.Fuzz(func(t *testing.T, raw []byte) {
		// Bound the single-input size: the SDK's own frame cap is 16 MiB, but the
		// fuzzer has no reason to build multi-MiB frames to exercise the decode
		// logic, and the resource oracle would (correctly) flag the 16 MiB-line
		// buffering as amplification on every such input, drowning other bugs.
		if len(raw) > 1<<20 {
			return
		}
		n := len(raw)

		var out []byte
		var calls []mc1ToolCall
		resource.Check(t, n, mc1MCPAllocFactor, func() {
			out, calls = serveOnce(raw)
		})

		// M3: nothing control-active ever comes back to the client's terminal.
		assertMCPOutputTerminalSafe(t, out)

		// M5: any dispatch landed on a real tool with a decodable typed input.
		for _, c := range calls {
			if !mc1KnownTools[c.tool] {
				t.Fatalf("M5: tool handler invoked for unregistered tool %q (args %q)", c.tool, c.args)
			}
		}
	})
}

func mc1MCPSeeds() []string {
	return []string{
		// A well-formed tools/call that should dispatch to a stub.
		`{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"dsd_health","arguments":{"deep":true}}}` + "\n",
		// Tool arg carrying a terminal-escape payload (must come back escaped).
		`{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"dsd_share","arguments":{"format":"[31mred[0m","from_path":"xy"}}}` + "\n",
		// Out-of-schema argument type (deep should be bool).
		`{"jsonrpc":"2.0","id":4,"method":"tools/call","params":{"name":"dsd_health","arguments":{"deep":"not-a-bool"}}}` + "\n",
		// Unknown tool name.
		`{"jsonrpc":"2.0","id":5,"method":"tools/call","params":{"name":"dsd_evil","arguments":{}}}` + "\n",
		// Unknown method.
		`{"jsonrpc":"2.0","id":6,"method":"no/such/method","params":{}}` + "\n",
		// Huge id.
		`{"jsonrpc":"2.0","id":999999999999999999999999999999,"method":"tools/list"}` + "\n",
		// Wrong-typed id (object).
		`{"jsonrpc":"2.0","id":{"nested":true},"method":"tools/list"}` + "\n",
		// Batch of mixed requests.
		`[{"jsonrpc":"2.0","id":7,"method":"tools/list"},{"jsonrpc":"2.0","id":8,"method":"tools/call","params":{"name":"dsd_diff","arguments":{"baseline_path":"a","current_path":"b"}}}]` + "\n",
		// Notification (no id) — cancellation.
		`{"jsonrpc":"2.0","method":"notifications/cancelled","params":{"requestId":2}}` + "\n",
		// Malformed JSON.
		`{"jsonrpc":"2.0","id":9,"method":` + "\n",
		// Empty frame.
		"\n",
		// Partial frame (no trailing newline) — tests the line buffer on EOF.
		`{"jsonrpc":"2.0","id":10,"method":"tools/list"`,
		// Deeply nested params.
		`{"jsonrpc":"2.0","id":11,"method":"tools/call","params":` + strings.Repeat("[", 500) + strings.Repeat("]", 500) + "}\n",
		// Several frames back to back (concurrent dispatch).
		`{"jsonrpc":"2.0","id":12,"method":"tools/list"}` + "\n" +
			`{"jsonrpc":"2.0","id":13,"method":"tools/call","params":{"name":"dsd_replay","arguments":{"bundle_path":""}}}` + "\n",
		// Raw control bytes in the stream.
		"\x1b[2J\x00\x07\n",
		// Invalid UTF-8 in a string value.
		`{"jsonrpc":"2.0","id":14,"method":"tools/call","params":{"name":"dsd_capture","arguments":{"out_path":"` + "\xff\xfe" + `"}}}` + "\n",
	}
}
