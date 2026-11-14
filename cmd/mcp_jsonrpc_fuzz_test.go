package cmd

// mcp_jsonrpc_fuzz_test.go — FuzzMCPJSONRPCToolArgs drives the real
// modelcontextprotocol/go-sdk server (JSON-RPC framing, method dispatch, tool
// input-schema validation, the SDK's own segmentio-based argument decoder)
// over an in-memory io.Pipe transport — no listener, no port — with tools
// registered under dsd's real names and real input structs. The bytes are
// attacker-shaped: in agentic use tools/call arguments are LLM-generated and
// can be prompt-injected (docs/THREAT_MODEL.md §5).
//
// Oracles (each one sound on its own, none of them panic-only):
//
//  1. Decode differential: whenever the SDK invokes a handler, the typed input
//     it handed over must equal what encoding/json (stdlib v1, the reference
//     semantics the SDK's segmentio decoder claims compatibility with) decodes
//     from the same raw `arguments` bytes. json/v2 is deliberately NOT the
//     reference: it is case-sensitive and rejects duplicate keys by design, so
//     every difference against it would be an expected difference, not a bug.
//  2. Framing: every line the server writes is a JSON object with
//     "jsonrpc":"2.0"; a response to one of our request ids appears at most once.
//  3. Liveness / bounded work: after the fuzzed frame, a ping request must be
//     answered within mcpFuzzDeadline — a malformed frame must neither wedge
//     the connection nor take unbounded time.
//  4. Path policy: every path argument a handler accepts through the real
//     safeBundlePath must be lexically contained in CWD per an independent
//     filepath.Rel check (same oracle as FuzzSafeBundlePathContainment, here
//     reached through the real SDK decode path).
//
// What this does NOT verify: the real tool bodies (the health pipeline, bundle
// I/O) — handlers here stop after argument decoding and safeBundlePath; output
// schema validation of real tool results; symlink resolution (oracle 4 is
// lexical — see the symlink reproducer in mcp_symlink_repro_test.go); the
// stdio transport's MaxLineLength cap (IOTransport with the default cap is
// used, not exercised with >1 MiB frames); concurrency between several
// in-flight tool calls (one fuzzed frame per iteration).

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

const mcpFuzzDeadline = 3 * time.Second

// mcpFuzzCall records one handler invocation: the tool name and the typed
// input the SDK decoded.
type mcpFuzzCall struct {
	tool string
	in   any
}

type mcpFuzzRecorder struct {
	mu        sync.Mutex
	calls     []mcpFuzzCall
	pathViols []string
}

func (r *mcpFuzzRecorder) record(tool string, in any, paths ...string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.calls = append(r.calls, mcpFuzzCall{tool: tool, in: in})
	for _, p := range paths {
		if p == "" {
			continue
		}
		cleaned, err := safeBundlePath(p)
		if err != nil {
			continue
		}
		if v := lexicallyEscapesCWD(cleaned); v != "" {
			r.pathViols = append(r.pathViols, fmt.Sprintf("%s: %q -> %q: %s", tool, p, cleaned, v))
		}
	}
}

func newMCPFuzzServer(rec *mcpFuzzRecorder) *mcp.Server {
	srv := mcp.NewServer(&mcp.Implementation{Name: "dsd", Version: "fuzz"}, nil)
	mcp.AddTool(srv, &mcp.Tool{Name: "dsd_health"}, func(_ context.Context, _ *mcp.CallToolRequest, in mcpHealthInput) (*mcp.CallToolResult, any, error) {
		rec.record("dsd_health", in)
		return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: "{}"}}}, nil, nil
	})
	mcp.AddTool(srv, &mcp.Tool{Name: "dsd_capture"}, func(_ context.Context, _ *mcp.CallToolRequest, in mcpCaptureInput) (*mcp.CallToolResult, mcpCaptureOutput, error) {
		rec.record("dsd_capture", in, in.OutPath)
		return nil, mcpCaptureOutput{}, nil
	})
	mcp.AddTool(srv, &mcp.Tool{Name: "dsd_replay"}, func(_ context.Context, _ *mcp.CallToolRequest, in mcpReplayInput) (*mcp.CallToolResult, any, error) {
		rec.record("dsd_replay", in, in.BundlePath)
		return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: "{}"}}}, nil, nil
	})
	mcp.AddTool(srv, &mcp.Tool{Name: "dsd_diff"}, func(_ context.Context, _ *mcp.CallToolRequest, in mcpDiffInput) (*mcp.CallToolResult, any, error) {
		rec.record("dsd_diff", in, in.BaselinePath, in.CurrentPath)
		return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: "[]"}}}, nil, nil
	})
	mcp.AddTool(srv, &mcp.Tool{Name: "dsd_share"}, func(_ context.Context, _ *mcp.CallToolRequest, in mcpShareInput) (*mcp.CallToolResult, any, error) {
		rec.record("dsd_share", in, in.FromPath)
		return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: "ok"}}}, nil, nil
	})
	return srv
}

// stdlibDecodeToolInput decodes raw tool arguments with encoding/json into the
// same Go type the real handler for tool declares.
func stdlibDecodeToolInput(tool string, raw json.RawMessage) (any, error) {
	dec := func(v any) error {
		if len(raw) == 0 || string(raw) == "null" {
			return nil
		}
		return json.Unmarshal(raw, v)
	}
	switch tool {
	case "dsd_health":
		var v mcpHealthInput
		return v, dec(&v)
	case "dsd_capture":
		var v mcpCaptureInput
		err := dec(&v)
		return v, err
	case "dsd_replay":
		var v mcpReplayInput
		err := dec(&v)
		return v, err
	case "dsd_diff":
		var v mcpDiffInput
		err := dec(&v)
		return v, err
	case "dsd_share":
		var v mcpShareInput
		err := dec(&v)
		return v, err
	}
	return nil, fmt.Errorf("unknown tool %q", tool)
}

var mcpFuzzToolNames = []string{"dsd_health", "dsd_capture", "dsd_replay", "dsd_diff", "dsd_share"}

// mcpFuzzSession is one server connection plus a line reader over its output.
type mcpFuzzSession struct {
	toSrv  *io.PipeWriter
	lines  chan string
	cancel context.CancelFunc
	done   chan struct{}
	// dupCheck enables the duplicate-response check for our own ids.
	dupCheck bool
	// closeOK: the server may end the session (a bounded, explicit outcome)
	// instead of answering. Set only after a raw fuzzed frame: the go-sdk
	// closes the connection on a frame it cannot decode as JSON-RPC 2.0
	// (e.g. "jsonrpc":"1.0" or non-UTF-8 garbage). That is not a hang, and raw
	// frames come from the trusted MCP client, not from the LLM. A hang is
	// still a failure in every mode, and closing on a well-formed tools/call
	// frame is still a failure.
	closeOK bool
}

func startMCPFuzzSession(t *testing.T, rec *mcpFuzzRecorder) *mcpFuzzSession {
	t.Helper()
	inR, inW := io.Pipe()
	outR, outW := io.Pipe()
	ctx, cancel := context.WithCancel(context.Background())
	srv := newMCPFuzzServer(rec)
	ss, err := srv.Connect(ctx, &mcp.IOTransport{Reader: inR, Writer: outW}, nil)
	if err != nil {
		cancel()
		t.Fatalf("server connect: %v", err)
	}
	s := &mcpFuzzSession{toSrv: inW, lines: make(chan string, 64), cancel: cancel, done: make(chan struct{})}
	go func() {
		defer close(s.done)
		sc := bufio.NewScanner(outR)
		sc.Buffer(make([]byte, 0, 64<<10), 8<<20)
		for sc.Scan() {
			s.lines <- sc.Text()
		}
		close(s.lines)
	}()
	go func() {
		_ = ss.Wait()
		_ = outW.Close()
	}()
	return s
}

func (s *mcpFuzzSession) close() {
	_ = s.toSrv.Close()
	s.cancel()
	// Drain so the reader goroutine can exit.
	go func() {
		for range s.lines { //nolint:revive // drain
		}
	}()
	select {
	case <-s.done:
	case <-time.After(mcpFuzzDeadline):
	}
}

func (s *mcpFuzzSession) send(t *testing.T, line string) bool {
	t.Helper()
	errCh := make(chan error, 1)
	go func() {
		_, err := io.WriteString(s.toSrv, line+"\n")
		errCh <- err
	}()
	select {
	case err := <-errCh:
		if err != nil {
			if s.closeOK {
				return false
			}
			t.Fatalf("server stopped reading input: %v (line %q)", err, truncateForMsg(line))
		}
	case <-time.After(mcpFuzzDeadline):
		t.Fatalf("bounded work: server did not consume a %d-byte frame within %v", len(line), mcpFuzzDeadline)
	}
	return true
}

// awaitID reads output lines until a response with the given id appears,
// validating the framing of every line seen on the way. It returns nil, false
// only when the server closed the session and closeOK permits that.
func (s *mcpFuzzSession) awaitID(t *testing.T, want string, seen map[string]int) (map[string]any, bool) {
	t.Helper()
	deadline := time.After(mcpFuzzDeadline)
	for {
		select {
		case line, ok := <-s.lines:
			if !ok {
				if s.closeOK {
					return nil, false
				}
				t.Fatalf("liveness: server closed its output before answering id %s", want)
			}
			var msg map[string]any
			if err := json.Unmarshal([]byte(line), &msg); err != nil {
				t.Fatalf("framing: server wrote a non-JSON line %q: %v", truncateForMsg(line), err)
			}
			if msg["jsonrpc"] != "2.0" {
				t.Fatalf("framing: server line without jsonrpc 2.0: %q", truncateForMsg(line))
			}
			rawID, hasID := msg["id"]
			if !hasID {
				continue // a notification (e.g. logging) — fine
			}
			key := fmt.Sprint(rawID)
			seen[key]++
			if seen[key] > 1 && s.dupCheck && strings.HasPrefix(key, mcpFuzzIDPrefix) {
				t.Fatalf("framing: response id %s delivered %d times", key, seen[key])
			}
			if key == want {
				return msg, true
			}
		case <-deadline:
			t.Fatalf("liveness/bounded work: no response to id %s within %v", want, mcpFuzzDeadline)
		}
	}
}

func truncateForMsg(s string) string {
	if len(s) > 300 {
		return s[:300] + "…"
	}
	return s
}

// lexicallyEscapesCWD is the independent containment check: it returns a
// non-empty reason when cleaned (a path safeBundlePath accepted) is not
// lexically inside the process CWD. Uses filepath.Rel, not prefix matching,
// so it cannot share safeBundlePath's own HasPrefix blind spot.
func lexicallyEscapesCWD(cleaned string) string {
	if mcpAllowAbsolutePaths {
		return ""
	}
	cwd, err := filepath.Abs(".")
	if err != nil {
		return ""
	}
	abs := cleaned
	if !filepath.IsAbs(abs) {
		abs = filepath.Join(cwd, abs)
	}
	rel, err := filepath.Rel(cwd, abs)
	if err != nil {
		return "filepath.Rel: " + err.Error()
	}
	if rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) || filepath.IsAbs(rel) {
		return "resolves outside CWD (rel=" + rel + ")"
	}
	return ""
}

// Our own request ids carry this prefix. A fuzzed frame containing it
// verbatim is skipped, and one containing any \u escape (which could spell
// it) disables the duplicate check, so a duplicate response to OUR id is
// always the server's fault, never a client that reused the id.
const mcpFuzzIDPrefix = "dsdfz-"

const mcpFuzzInit = `{"jsonrpc":"2.0","id":"dsdfz-init","method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"fuzz","version":"0"}}}`
const mcpFuzzPing = `{"jsonrpc":"2.0","id":"dsdfz-ping","method":"ping"}`
const mcpFuzzInitialized = `{"jsonrpc":"2.0","method":"notifications/initialized","params":{}}`

func FuzzMCPJSONRPCToolArgs(f *testing.F) {
	// mode 0: raw frame verbatim; mode 1: tools/call with fuzzed arguments.
	f.Add(uint8(1), uint8(1), `{"out_path":"x.tar.gz","sanitize":true}`)
	f.Add(uint8(1), uint8(3), `{"baseline_path":"a","current_path":"b"}`)
	f.Add(uint8(1), uint8(1), `{"out_path":"/etc/passwd"}`)
	f.Add(uint8(1), uint8(1), `{"OUT_PATH":"../x","out_path":"ok"}`)
	f.Add(uint8(1), uint8(3), `{"baſeline_path":"/etc/shadow","current_path":"b"}`)
	f.Add(uint8(1), uint8(4), `{"format":"md","from_path":"a\u0000b"}`)
	f.Add(uint8(1), uint8(2), `{"bundle_path":"\ud800x"}`)
	f.Add(uint8(1), uint8(0), `{"deep":"true"}`)
	f.Add(uint8(1), uint8(0), `null`)
	f.Add(uint8(1), uint8(0), `[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]`)
	f.Add(uint8(0), uint8(0), `{"jsonrpc":"2.0","id":5,"method":"tools/list"}`)
	f.Add(uint8(0), uint8(0), `{"jsonrpc":"2.0","id":5,"method":"tools/call","params":{"name":"dsd_replay","arguments":{"bundle_path":"x"}},"id":6}`)
	f.Add(uint8(0), uint8(0), `{"jsonrpc":"2.0","id":null,"method":"ping"}`)
	f.Add(uint8(0), uint8(0), `{"jsonrpc":"1.0","id":5,"method":"ping"}`)
	f.Add(uint8(0), uint8(0), `{"jsonrpc":"2.0","id":5,"method":"notifications/cancelled","params":{"requestId":5}}`)
	f.Add(uint8(0), uint8(0), "\xff\xfe{")

	f.Fuzz(func(t *testing.T, mode, toolIdx uint8, payload string) {
		if len(payload) > 1<<16 || strings.Contains(payload, mcpFuzzIDPrefix) {
			return
		}
		rec := &mcpFuzzRecorder{}
		s := startMCPFuzzSession(t, rec)
		defer func() {
			s.close()
			rec.mu.Lock()
			defer rec.mu.Unlock()
			for _, v := range rec.pathViols {
				t.Errorf("path policy: %s", v)
			}
		}()
		s.dupCheck = !strings.Contains(payload, `\u`)
		seen := map[string]int{}

		s.send(t, mcpFuzzInit)
		_, _ = s.awaitID(t, "dsdfz-init", seen)
		s.send(t, mcpFuzzInitialized)

		var tool string
		var frame string
		var probe struct {
			Params struct {
				Arguments json.RawMessage `json:"arguments"`
			} `json:"params"`
		}
		stdlibOK := false
		if mode%2 == 1 {
			tool = mcpFuzzToolNames[int(toolIdx)%len(mcpFuzzToolNames)]
			frame = `{"jsonrpc":"2.0","id":"dsdfz-call","method":"tools/call","params":{"name":"` + tool + `","arguments":` + payload + `}}`
			// Only a frame that is one well-formed JSON object for the stdlib
			// too must be answered; otherwise the server may legitimately
			// answer with a parse error carrying a null id, or close.
			stdlibOK = !strings.ContainsAny(payload, "\n\r") && json.Unmarshal([]byte(frame), &probe) == nil
		} else {
			frame = payload
		}
		s.closeOK = !stdlibOK
		// A frame with embedded newlines is several frames on this transport;
		// that is legitimate input, not a harness bug.
		if !s.send(t, frame) {
			return
		}

		if mode%2 == 1 {
			if stdlibOK {
				if _, ok := s.awaitID(t, "dsdfz-call", seen); !ok {
					return
				}
			}
			// Liveness probe, then compare whatever the handlers saw.
			if !s.send(t, mcpFuzzPing) {
				return
			}
			if _, ok := s.awaitID(t, "dsdfz-ping", seen); !ok {
				return
			}

			rec.mu.Lock()
			calls := append([]mcpFuzzCall(nil), rec.calls...)
			rec.mu.Unlock()
			if len(calls) > 0 && !stdlibOK {
				t.Fatalf("decode differential: SDK invoked %s for a frame encoding/json rejects: %q", calls[0].tool, truncateForMsg(frame))
			}
			for _, c := range calls {
				if c.tool != tool {
					t.Fatalf("dispatch: asked for %s, SDK invoked %s", tool, c.tool)
				}
				want, err := stdlibDecodeToolInput(c.tool, probe.Params.Arguments)
				if err != nil {
					t.Fatalf("decode differential: SDK decoded %s args %q to %+v, encoding/json rejects them: %v", c.tool, truncateForMsg(string(probe.Params.Arguments)), c.in, err)
				}
				if !reflect.DeepEqual(want, c.in) {
					t.Fatalf("decode differential: %s args %q\n  SDK (segmentio): %#v\n  encoding/json:   %#v", c.tool, truncateForMsg(string(probe.Params.Arguments)), c.in, want)
				}
			}
			return
		}

		if !s.send(t, mcpFuzzPing) {
			return
		}
		_, _ = s.awaitID(t, "dsdfz-ping", seen)
	})
}
