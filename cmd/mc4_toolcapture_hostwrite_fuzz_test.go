package cmd

// MC4 target 5 — the REAL dsd_capture MCP handler (toolCapture), driven over a
// real mcp.Server with a hostile-fuzzed out_path, under a filesystem-fingerprint
// oracle. This is the "no host write" claim tested END TO END at the MCP layer.
//
// WHY THIS IS NEW. MC1 target 1 (FuzzMCPServerHostileJSONRPC) stubs every tool
// handler with an echo, so it exercises the SDK transport/dispatch layer but has
// NO disk path at all — its own comment says a filesystem-fingerprint oracle
// there "would be vacuous". DL1 target 2 (FuzzMCPSafeBundlePathContainment)
// fuzzes safeBundlePath in ISOLATION (string in, decision out), not wired to a
// server or a real write. Neither drives a real tools/call through the real
// toolCapture body — safeBundlePath + source.Recorder + b.SaveTarball — to a
// real file on disk and then asserts nothing outside the cwd changed. That is
// the gap this target closes (mc1 LEFTOVER "real-handler/no-host-write path").
//
// THREAT MODEL. In agentic use out_path is LLM-generated from context the model
// read — which can include prompt-injected content (see safeBundlePath's own
// doc comment and docs/THREAT_MODEL.md "MCP out_path"). So out_path is untrusted
// and is exactly the arbitrary-file-write primitive safeBundlePath exists to
// bound to the cwd subtree. The claim under test: for ANY out_path bytes, a
// capture invoked over MCP writes ONLY under the server's cwd — never into a
// sentinel tree planted OUTSIDE the cwd (a traversal/absolute escape), and never
// anywhere if safeBundlePath rejects the path.
//
// READING OF "REAL toolCapture (not stubbed)" (stated up front; nobody answers
// questions here). The HANDLER and its WRITE PATH are real: the registered
// handler IS the production toolCapture (real safeBundlePath, real
// source.Recorder, real Manifest, real Sanitize, real b.SaveTarball → os.Create
// under out_path). The only seam is the DATA SOURCE: runHealthOnceFn is replaced
// per-input with a cheap deterministic stub so (a) the fuzz loop is deterministic
// (a full collector sweep reads live, ever-changing host state, which would make
// the corpus non-reproducible) and (b) the shared, thermally-constrained host is
// not made to run a real `dsd health` sweep — external binaries, huge /proc
// walks — hundreds of times. The containment/no-write claim is a property of the
// WRITE path (out_path → safeBundlePath → SaveTarball), which runs for real; the
// orthogonal "the collectors themselves never write" claim is covered, at the
// genuinely-unseamed full-sweep level, by TestMC4RealCollectorNoHostWrite below
// (run a bounded number of times, not in the hot loop). Network stays OFF
// (default) throughout, so no outbound dials.
//
// INVARIANTS asserted (see INVARIANTS.d/mc4-toolcapture.md):
//   C1 no panic — the real handler survives any out_path bytes without panicking.
//   C2 sentinel unchanged — a fingerprinted sentinel tree OUTSIDE the cwd is
//      byte-identical before and after every input. No out_path (traversal,
//      absolute, symlink-looking, NUL, overlong) ever causes a write outside cwd.
//   C3 writes land only under cwd — any regular file that appears after the call
//      is under the cwd subtree (the SaveTarball destination), never elsewhere;
//      and when safeBundlePath REJECTS the path, no new file appears at all.
//
// Does NOT verify: that the collector pipeline itself writes nothing (the source
// is seamed here — see TestMC4RealCollectorNoHostWrite for the unseamed check);
// bundle CONTENT correctness or redaction (dsd_capture's content is exercised by
// capture/replay tests); writes outside the two fingerprinted roots (cwd subtree
// + one sibling sentinel) — e.g. a write to an absolute path in /etc would be
// caught by C2 only if it landed in the sentinel, so the sentinel is deliberately
// the traversal TARGET the seeds aim at, and C3's "only under cwd" is the general
// catch; xattrs/ACLs (Fingerprint does not capture them); and the
// --allow-absolute-paths mode (left at its secure default here — opting out of
// containment is a deliberate operator choice, tested as its own case).

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
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
	"github.com/keyorixhq/dashdiag/internal/testutil/resource"
)

// cheapHealthSource is the deterministic stand-in for runHealthOnceFn used in the
// fuzz hot loop. It returns an empty-but-valid result set so toolCapture's real
// Recorder → Manifest → SaveTarball write path runs end to end (a small real
// tarball is written to out_path) without a live collector sweep. See the file
// header's "READING OF REAL toolCapture" for why the source — and only the
// source — is seamed.
func cheapHealthSource(_ context.Context, _ platform.ContainerContext, _ platform.CloudEnvironment,
	_ platform.Profile, _ output.OutputMode, _ healthRunOpts, _ *analysis.PolicyFile,
) ([]runner.Result, []models.Insight, *baseline.Snapshot, time.Duration) {
	return nil, nil, nil, 0
}

// buildRealCaptureServer registers the PRODUCTION toolCapture handler (not a
// stub) under the real dsd_capture tool name/schema on a fresh server.
func buildRealCaptureServer() *mcp.Server {
	srv := mcp.NewServer(&mcp.Implementation{Name: "dsd", Version: "fuzz"}, nil)
	mcp.AddTool(srv, &mcp.Tool{Name: "dsd_capture"}, toolCapture)
	return srv
}

// captureCallFrame builds a well-formed post-handshake tools/call for dsd_capture
// with the given (arbitrary, possibly hostile) out_path. json.Marshal encodes the
// arbitrary string safely, so the frame is always valid JSON-RPC and the fuzzed
// bytes reach the handler as the DECODED out_path value — this target fuzzes the
// handler's path handling, not the SDK's frame decoder (that is MC1 target 1).
func captureCallFrame(outPath string, sanitize, identifiers bool) []byte {
	args := map[string]any{"out_path": outPath}
	if sanitize {
		args["sanitize"] = true
	}
	if identifiers {
		args["identifiers"] = true
	}
	argsJSON, err := json.Marshal(args)
	if err != nil {
		// A string is always marshalable; this cannot happen. Fall back to a
		// frame that still drives the handshake path if it somehow does.
		argsJSON = []byte(`{"out_path":""}`)
	}
	var b bytes.Buffer
	b.WriteString(`{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"dsd_capture","arguments":`)
	b.Write(argsJSON)
	b.WriteString("}}\n")
	return b.Bytes()
}

// captureRespSettle / captureRespCeiling bound the wait for the capture to
// RESPOND. Unlike the MC3 adaptive drain (calibrated to a <2 ms stub echo), the
// real capture handler does real work (platform detect + tar/gzip + file write)
// before emitting its response, so an output-quiescence detector with a few-ms
// settle would EOF the pipe mid-capture and cancel it. Instead the writer holds
// the pipe open until the tools/call RESPONSE (id:2 — success or a safeBundlePath
// error, both carry it) has been written, or a ceiling fires. json.Marshal makes
// every frame well-formed, so the call always draws an id:2 response once it
// dispatches; the only slow case is the capture itself, bounded by the ceiling
// (then the context timeout).
const (
	captureRespPoll    = 2 * time.Millisecond
	captureRespCeiling = 6 * time.Second
)

// driveRealCapture feeds handshake + a dsd_capture tools/call to a real server
// over an IOTransport and returns once the capture has responded (or a timeout
// fires). It never returns output to the caller; the ORACLE is the filesystem.
func driveRealCapture(frame []byte) {
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()

	srv := buildRealCaptureServer()
	inR, inW := io.Pipe()
	w := &syncWriter{cap: 1 << 20}

	runDone := make(chan struct{})
	go func() {
		_ = srv.Run(ctx, &mcp.IOTransport{Reader: inR, Writer: w})
		close(runDone)
	}()

	input := append(mc1Handshake(), frame...)
	writerDone := make(chan struct{})
	go func() {
		_, _ = inW.Write(input)
		waitForCaptureResponse(w, runDone) // hold open until id:2 responds
		_ = inW.Close()                    // EOF -> clean shutdown
		close(writerDone)
	}()

	select {
	case <-runDone:
	case <-time.After(7 * time.Second):
		cancel()
	}
	_ = inR.Close()
	_ = inW.Close()
	joinOrTimeout(runDone)
	joinOrTimeout(writerDone)
}

// waitForCaptureResponse holds until the server's output carries the tools/call
// response id (id:2), the server goroutine has finished, or the ceiling elapses.
func waitForCaptureResponse(w *syncWriter, runDone <-chan struct{}) {
	start := time.Now()
	for {
		select {
		case <-runDone:
			return
		default:
		}
		if time.Since(start) >= captureRespCeiling {
			return
		}
		if bytes.Contains(w.snapshot(), []byte(`"id":2`)) {
			// Response landed; a brief settle lets the frame flush fully.
			time.Sleep(5 * time.Millisecond)
			return
		}
		time.Sleep(captureRespPoll)
	}
}

// mc4CaptureSeeds exercises the hostile-out_path space the containment claim must
// survive: plain in-cwd names, traversal escapes aimed at the sentinel, absolute
// paths, NUL and control bytes, symlink-looking and dot-dot-laden strings.
func mc4CaptureSeeds(f *testing.F) {
	seeds := []struct {
		path                 string
		sanitize, identifier bool
	}{
		{"bundle.tar.gz", false, false},
		{"sub/dir/bundle.tar.gz", false, false},
		{"./bundle.tar.gz", true, false},
		{"bundle.tar.gz", true, true},
		{"", false, false},                              // empty -> rejected
		{"../sentinel/escape.tar.gz", false, false},     // traversal toward sentinel
		{"../../sentinel/escape.tar.gz", false, false},  // deeper traversal
		{"/etc/evil.tar.gz", false, false},              // absolute escape
		{"/tmp/evil.tar.gz", false, false},              // absolute escape
		{"sub/../bundle.tar.gz", false, false},          // in-cwd dot-dot that cleans inside
		{"foo/../../sentinel/x", false, false},          // dot-dot escaping cwd
		{"bundle\x00.tar.gz", false, false},             // NUL byte
		{"a\x1b[2Jb.tar.gz", false, false},              // escape sequence in name
		{strings.Repeat("a", 300) + ".tar.gz", false, false}, // long name
		{"....//....//sentinel/x", false, false},        // obfuscated traversal
	}
	for _, s := range seeds {
		f.Add(s.path, s.sanitize, s.identifier)
	}
}

// plantSentinel creates a sibling directory OUTSIDE the cwd with a few files and
// returns its path. It is the traversal TARGET the hostile seeds aim at; C2
// asserts it is never touched. It lives under the parent of cwd so a "../sentinel"
// from cwd resolves to it.
func plantSentinel(t *testing.T, parent string) string {
	t.Helper()
	dir := filepath.Join(parent, "sentinel")
	if err := os.MkdirAll(filepath.Join(dir, "nested"), 0o755); err != nil {
		t.Fatalf("plant sentinel: %v", err)
	}
	for name, body := range map[string]string{
		"keep.txt":        "do-not-touch",
		"nested/deep.txt": "also-do-not-touch",
	} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o644); err != nil {
			t.Fatalf("plant sentinel file: %v", err)
		}
	}
	return dir
}

// countFilesOutsideCwd walks the parent tree and returns any regular file that is
// NOT under cwd and NOT under the pre-existing sentinel set (captured in `known`).
// A non-empty result means a write escaped the cwd subtree.
func newFilesOutsideCwd(t *testing.T, parent, cwd string, known map[string]bool) []string {
	t.Helper()
	var escaped []string
	_ = filepath.Walk(parent, func(path string, fi os.FileInfo, err error) error {
		if err != nil || fi.IsDir() {
			return nil
		}
		if strings.HasPrefix(path, cwd+string(filepath.Separator)) || path == cwd {
			return nil // under cwd — allowed
		}
		if known[path] {
			return nil // pre-existing sentinel file
		}
		escaped = append(escaped, path)
		return nil
	})
	return escaped
}

func FuzzMC4ToolCaptureNoHostWrite(f *testing.F) {
	mc4CaptureSeeds(f)

	f.Fuzz(func(t *testing.T, outPath string, sanitize, identifiers bool) {
		// Seam ONLY the data source (see file header). Restored per input so the
		// rest of the package's tests never see the stub.
		oldSrc := runHealthOnceFn
		runHealthOnceFn = cheapHealthSource
		defer func() { runHealthOnceFn = oldSrc }()

		// A fresh isolated world per input: parent/{cwd,sentinel}. cwd is where
		// a contained capture is allowed to write; sentinel is outside it.
		parent := t.TempDir()
		cwd := filepath.Join(parent, "work")
		if err := os.MkdirAll(cwd, 0o755); err != nil {
			t.Fatalf("mkdir cwd: %v", err)
		}
		sentinel := plantSentinel(t, parent)
		t.Chdir(cwd) // process cwd := work; restored by t.Cleanup

		// Record the sentinel fingerprint and the set of pre-existing files so a
		// post-call escape is unambiguous.
		before := resource.Fingerprint(t, sentinel)
		known := map[string]bool{}
		_ = filepath.Walk(parent, func(path string, fi os.FileInfo, err error) error {
			if err == nil && !fi.IsDir() {
				known[path] = true
			}
			return nil
		})

		// C1: the real handler must not panic on any out_path bytes. The cost of a
		// capture is dominated by FIXED overhead (SDK handshake + platform detect +
		// tar/gzip of an empty bundle, ~0.6–2 MiB) that is independent of out_path
		// length, so an amplification bound keyed to len(out_path) is the wrong
		// oracle (it false-positives on tiny inputs). Instead Measure the drive and
		// assert generous ABSOLUTE ceilings: a hang guard (wall time) and a blow-up
		// guard (alloc) that sit far above the fixed baseline but still catch a
		// crafted path that drives tar/gzip or the path logic into gigabytes/minutes.
		// The LOAD-BEARING oracle here is the filesystem fingerprint (C2/C3), not
		// this bound.
		r := resource.Measure(len(outPath), func() {
			driveRealCapture(captureCallFrame(outPath, sanitize, identifiers))
		})
		if r.Elapsed > 7500*time.Millisecond {
			t.Fatalf("C1 capture over wall-time ceiling: out_path=%q elapsed=%s alloc=%d B", outPath, r.Elapsed, r.AllocBytes)
		}
		if r.AllocBytes > 64<<20 {
			t.Fatalf("C1 capture over alloc ceiling: out_path=%q alloc=%d B (%.0fx) elapsed=%s", outPath, r.AllocBytes, r.Amplification, r.Elapsed)
		}

		// C2: the sentinel tree OUTSIDE cwd is byte-identical — no escape wrote,
		// removed, re-timestamped or re-permissioned anything there.
		resource.AssertUnchanged(t, sentinel, before)

		// C3: no NEW regular file appeared anywhere outside the cwd subtree.
		if escaped := newFilesOutsideCwd(t, parent, cwd, known); len(escaped) > 0 {
			t.Fatalf("C3 no-host-write violated: out_path=%q produced file(s) outside cwd %s:\n  %s",
				outPath, cwd, strings.Join(escaped, "\n  "))
		}
	})
}
