package cmd

// mcp.go — `dsd mcp`: MCP (Model Context Protocol) server over stdio.
//
// Exposes four tools that give an AI agent structured, citable host context:
//   dsd_health   — run the health pipeline and return the JSON verdict
//   dsd_capture  — record a raw bundle for offline replay/diff
//   dsd_replay   — replay a bundle and return its JSON verdict
//   dsd_diff     — diff two bundles and return per-check status transitions
//
// All tools are thin wrappers over existing code paths; no new collector or
// verdict logic lives here. The output of every tool is the existing
// render.JSONOutput shape (or a DiffEntry[] array), inheriting the frozen
// schema/dsd-output.json 1.x stability promise.
//
// Transport: stdio only (JSON-RPC 2.0). Register in Claude Code with:
//   claude mcp add dsd -- dsd mcp
//
// See docs/MCP_DESIGN.md for full design rationale and non-goals.

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/spf13/cobra"

	"github.com/keyorixhq/dashdiag/internal/baseline"
	"github.com/keyorixhq/dashdiag/internal/collectors"
	"github.com/keyorixhq/dashdiag/internal/cvedata"
	"github.com/keyorixhq/dashdiag/internal/output"
	"github.com/keyorixhq/dashdiag/internal/platform"
	"github.com/keyorixhq/dashdiag/internal/render"
	"github.com/keyorixhq/dashdiag/internal/source"
	"github.com/keyorixhq/dashdiag/internal/version"
)

func init() {
	rootCmd.AddCommand(mcpCmd)
}

var mcpCmd = &cobra.Command{
	Use:   "mcp",
	Short: "MCP server — expose dsd tools to AI agents over stdio",
	Long: `Start a Model Context Protocol (MCP) server that speaks JSON-RPC 2.0 over
stdin/stdout. This lets AI agents (Claude Code, Cursor, etc.) call dsd's
diagnosis tools directly and cite the results as citable host evidence.

Four tools are exposed:
  dsd_health   — run the full health pipeline (same as dsd health --json)
  dsd_capture  — record a raw bundle to a file for offline replay
  dsd_replay   — replay a bundle and return its health verdict as JSON
  dsd_diff     — diff two bundles, returning per-check status transitions

Register in Claude Code:
  claude mcp add dsd -- dsd mcp

See docs/MCP_DESIGN.md for architecture, security model, and non-goals.`,
	// Suppress the version/platform line that runE's PersistentPreRun emits.
	PersistentPreRun: func(_ *cobra.Command, _ []string) {},
	RunE:             runMCP,
}

// ── input/output structs (drive JSON Schema auto-generation by MCP SDK) ───

type mcpHealthInput struct {
	Deep bool `json:"deep,omitempty" jsonschema:"run extended analysis: per-core CPU breakdown and top memory/IO consumers"`
	CVE  bool `json:"cve,omitempty"  jsonschema:"include CVE security advisory scan (CVSS>=7 WARN; >=9 or CISA KEV CRIT; may be slow)"`
}

type mcpCaptureInput struct {
	OutPath     string `json:"out_path"              jsonschema:"destination file path for the bundle (e.g. /tmp/host.tar.gz)"`
	Sanitize    bool   `json:"sanitize,omitempty"    jsonschema:"best-effort redaction of credentials from the bundle before writing"`
	Identifiers bool   `json:"identifiers,omitempty" jsonschema:"also redact IPv4, MAC, and hostname (implies sanitize)"`
}

type mcpCaptureOutput struct {
	BundlePath string `json:"bundle_path"`
	Host       string `json:"host"`
	CapturedAt string `json:"captured_at"`
	Bytes      int64  `json:"bytes"`
	// Sanitized and Note are additive (sanitize-bundle-03): dsd capture --raw
	// prints a prominent stderr warning when a bundle is unredacted, but an
	// MCP caller has no stderr a human would see — without these fields it
	// got a bundle_path back with zero signal the contents are raw. Note
	// carries the identical wording the CLI's own warning uses (see
	// sanitizeDisclosureNote in capture_raw.go), so the two entry points can
	// never drift out of sync on what they disclose. mcpCaptureOutput is not
	// render.JSONOutput and carries no schema/dsd-output.json stability
	// promise (see docs/MCP_DESIGN.md's own tool table, which documents
	// dsd_capture's output as this separate ad-hoc shape) — adding fields
	// here is not a breaking change to that frozen contract.
	Sanitized bool   `json:"sanitized"`
	Note      string `json:"note"`
}

type mcpReplayInput struct {
	BundlePath string `json:"bundle_path" jsonschema:"path to a bundle created with dsd_capture or dsd capture --raw"`
}

type mcpDiffInput struct {
	BaselinePath string `json:"baseline_path" jsonschema:"path to the baseline (before) bundle"`
	CurrentPath  string `json:"current_path"  jsonschema:"path to the current (after) bundle"`
}

// safeBundlePath rejects paths that contain traversal sequences. MCP is
// stdio-only and the caller is a trusted local process, so we allow any
// absolute or relative path — we only block ".." components that could escape
// an expected directory.
func safeBundlePath(raw string) (string, error) {
	if raw == "" {
		return "", fmt.Errorf("path must not be empty")
	}
	cleaned := filepath.Clean(raw)
	if strings.Contains(cleaned, "..") {
		return "", fmt.Errorf("path must not contain traversal sequences")
	}
	return cleaned, nil
}

// ── tool handlers ──────────────────────────────────────────────────────────

// mcpPipelineMu serializes every MCP tool handler that touches the shared,
// process-global health-pipeline state: collectors.activeSource (an
// atomic.Pointer, but "swap in a Recorder/Replay, run the pipeline, swap the
// previous Source back" is a multi-step transaction the atomicity of the
// individual load/store does NOT make safe under concurrency) and, via
// replayBundle, platform's identity/replay-platform overrides. The MCP SDK
// runs concurrent tool calls (jsonrpc2.Async for every non-initialize
// request), so without this a dsd_capture running concurrently with a
// dsd_health/dsd_replay/dsd_diff call could have the OTHER call's collectors
// silently read through (or tee into) this call's Recorder/Replay — cross-
// contaminating a capture bundle or a live health result with data that was
// never actually observed together. dsd_capture/replay/diff already cost
// several seconds each (a full collector sweep), so serializing here is not
// a meaningful throughput concern for a diagnostic tool.
var mcpPipelineMu sync.Mutex

// runHealthOnceFn is runHealthOnce by default. It's a package-level seam so
// tests can substitute a stub that captures the ctx it receives, to verify
// that toolHealth/toolCapture forward the caller's real request-scoped
// context instead of silently substituting context.Background() (which would
// make the JSON-RPC caller's own cancellation/timeout unable to bound the
// underlying collector run).
var runHealthOnceFn = runHealthOnce

// mcpToolTimeout additionally bounds toolHealth/toolCapture's collector run
// on top of whatever cancellation the caller's own ctx carries — the MCP SDK
// dispatches tools/call with jsonrpc2.Async, so ctx IS a real per-request
// context, but a client that never cancels still needs a backstop. Matches
// the product's own <35s completion promise plus headroom for toolCapture's
// tar/gzip write. Without this, a single hung collector (a real network dial
// with no timeout of its own, a filtered egress path in a sandboxed
// environment) had nothing bounding the MCP call if the caller didn't cancel.
const mcpToolTimeout = 40 * time.Second

// toolHealth runs the full health pipeline and returns the JSON verdict.
// Equivalent to `dsd health --json [--deep] [--cve]`.
func toolHealth(ctx context.Context, _ *mcp.CallToolRequest, in mcpHealthInput) (
	*mcp.CallToolResult, any, error,
) {
	mcpPipelineMu.Lock()
	defer mcpPipelineMu.Unlock()

	ctx, cancel := context.WithTimeout(ctx, mcpToolTimeout)
	defer cancel()
	ctrCtx := collectors.ContainerContextViaSource()
	cloudEnv := collectors.CloudEnvironmentViaSource()
	profile := collectors.ProfileViaSource()

	results, insights, _, _ := runHealthOnceFn(ctx, ctrCtx, cloudEnv, profile,
		output.ModePlain, healthRunOpts{IncludeDeep: in.Deep, IncludeCVE: in.CVE, Terse: !in.Deep}, nil)

	data, err := render.RenderJSON(results, insights)
	if err != nil {
		return nil, nil, fmt.Errorf("dsd_health: marshalling result: %w", err)
	}
	// checks[].raw is documented out-of-contract: nothing stops a collector's raw
	// Data from carrying secret-shaped content (a config blob, command output, a
	// credential). Unlike `dsd capture --raw`'s file-write path, this MCP
	// response has no sanitize opt-in at all and commonly forwards straight into
	// a cloud-hosted LLM's context — so give it the same "secrets always
	// redacted" floor a capture bundle gets, best-effort.
	data = redactMCPJSON(data)
	return &mcp.CallToolResult{
		Content: []mcp.Content{&mcp.TextContent{Text: string(data)}},
	}, nil, nil
}

// redactMCPJSON applies source.RedactJSONSecrets to an MCP tool's outbound
// JSON payload, falling back to the original bytes unchanged if the payload
// somehow isn't valid JSON (render.RenderJSON output always is, in practice —
// this is defense against a future caller misuse, not an expected path).
func redactMCPJSON(data []byte) []byte {
	red, err := source.RedactJSONSecrets(data)
	if err != nil {
		return data
	}
	return red
}

// toolCapture records a raw bundle, writing it to in.OutPath.
// Equivalent to `dsd capture --raw [--sanitize] [--identifiers] --out <path>`.
func toolCapture(ctx context.Context, _ *mcp.CallToolRequest, in mcpCaptureInput) (
	*mcp.CallToolResult, mcpCaptureOutput, error,
) {
	mcpPipelineMu.Lock()
	defer mcpPipelineMu.Unlock()

	outPath, err := safeBundlePath(in.OutPath)
	if err != nil {
		return nil, mcpCaptureOutput{}, fmt.Errorf("dsd_capture: invalid out_path: %w", err)
	}
	if in.Identifiers {
		in.Sanitize = true
	}

	ctx, cancel := context.WithTimeout(ctx, mcpToolTimeout)
	defer cancel()
	ctrCtx := platform.DetectContainerContext()
	cloudEnv := platform.DetectCloudEnvironment()
	profile := platform.Detect()

	rec := source.NewRecorder(collectors.ActiveSource())
	prev := collectors.SetSource(rec)
	defer collectors.SetSource(prev)

	gpu := detectGPUPresence()
	results, insights, _, _ := runHealthOnceFn(ctx, ctrCtx, cloudEnv, profile,
		output.ModePlain, healthRunOpts{Terse: true, IncludeGPU: gpu}, nil)

	b := rec.Bundle()
	host := hostnameOr("host")
	b.Manifest = source.Manifest{
		Format:     source.FormatVersion,
		Host:       host,
		OS:         osPretty(),
		GOOS:       runtime.GOOS,
		DistroID:   cvedata.DetectDistroID(),
		InitSystem: profile.InitSystem,
		Kernel:     kernelRelease(),
		DsdVer:     version.Version,
		Created:    time.Now().UTC().Format(time.RFC3339),
		Note:       "dsd mcp capture",
	}
	if data, err := render.RenderJSON(results, insights); err == nil {
		b.PutFile("/__dsd__/health.json", data)
	}

	var sanReport source.SanitizeReport
	if in.Sanitize {
		sanReport = b.Sanitize(source.SanitizeOptions{Identifiers: in.Identifiers})
	}
	if err := b.SaveTarball(outPath); err != nil {
		return nil, mcpCaptureOutput{}, fmt.Errorf("dsd_capture: writing bundle: %w", err)
	}

	fi, statErr := os.Stat(outPath)
	var sz int64
	if statErr == nil {
		sz = fi.Size()
	}
	// Report the SANITIZED host (b.Manifest.Host, which Sanitize replaced with
	// the placeholder) when identifiers redaction was requested — otherwise the
	// tool's own JSON response discloses the real hostname on a channel
	// Sanitize was never applied to, defeating the point of asking for it.
	respHost := host
	if in.Identifiers {
		respHost = b.Manifest.Host
	}
	return nil, mcpCaptureOutput{
		BundlePath: outPath,
		Host:       respHost,
		CapturedAt: b.Manifest.Created,
		Bytes:      sz,
		Sanitized:  in.Sanitize,
		Note:       sanitizeDisclosureNote(in.Sanitize, in.Identifiers, sanReport),
	}, nil
}

// toolReplay replays a bundle and returns the JSON health verdict for the
// captured host. Equivalent to `dsd replay <bundle> --json`.
func toolReplay(_ context.Context, _ *mcp.CallToolRequest, in mcpReplayInput) (
	*mcp.CallToolResult, any, error,
) {
	mcpPipelineMu.Lock()
	defer mcpPipelineMu.Unlock()

	bundlePath, err := safeBundlePath(in.BundlePath)
	if err != nil {
		return nil, nil, fmt.Errorf("dsd_replay: invalid bundle_path: %w", err)
	}
	b, err := loadBundle(bundlePath)
	if err != nil {
		return nil, nil, fmt.Errorf("dsd_replay: loading bundle: %w", err)
	}
	results, insights, _ := replayBundle(b, false, false, false, false)
	data, err := render.RenderJSON(results, insights)
	if err != nil {
		return nil, nil, fmt.Errorf("dsd_replay: marshalling result: %w", err)
	}
	// See toolHealth's redactMCPJSON call: checks[].raw can carry a collector's
	// verbatim raw data (here, from the replayed bundle), and this response has
	// no sanitize opt-in of its own.
	data = redactMCPJSON(data)
	return &mcp.CallToolResult{
		Content: []mcp.Content{&mcp.TextContent{Text: string(data)}},
	}, nil, nil
}

// toolDiff diffs two capture bundles and returns the per-check status
// transitions as a JSON array. Equivalent to `dsd diff <baseline> <current> --json`.
func toolDiff(_ context.Context, _ *mcp.CallToolRequest, in mcpDiffInput) (
	*mcp.CallToolResult, any, error,
) {
	mcpPipelineMu.Lock()
	defer mcpPipelineMu.Unlock()

	baselinePath, err := safeBundlePath(in.BaselinePath)
	if err != nil {
		return nil, nil, fmt.Errorf("dsd_diff: invalid baseline_path: %w", err)
	}
	currentPath, err := safeBundlePath(in.CurrentPath)
	if err != nil {
		return nil, nil, fmt.Errorf("dsd_diff: invalid current_path: %w", err)
	}
	base, err := loadBundle(baselinePath)
	if err != nil {
		return nil, nil, fmt.Errorf("dsd_diff: loading baseline: %w", err)
	}
	current, err := loadBundle(currentPath)
	if err != nil {
		return nil, nil, fmt.Errorf("dsd_diff: loading current: %w", err)
	}
	_, _, baseSnap := replayBundle(base, false, false, false, false)
	_, _, curSnap := replayBundle(current, false, false, false, false)
	entries := baseline.ComputeDiff(baseSnap, curSnap)
	data, err := json.Marshal(entries)
	if err != nil {
		return nil, nil, fmt.Errorf("dsd_diff: marshalling diff: %w", err)
	}
	return &mcp.CallToolResult{
		Content: []mcp.Content{&mcp.TextContent{Text: string(data)}},
	}, nil, nil
}

// ── server ─────────────────────────────────────────────────────────────────

func runMCP(_ *cobra.Command, _ []string) error {
	srv := mcp.NewServer(&mcp.Implementation{
		Name:    "dsd",
		Version: version.Version,
	}, nil)

	mcp.AddTool(srv, &mcp.Tool{
		Name: "dsd_health",
		Description: "Run the DashDiag health pipeline on the local host and return a scored " +
			"health verdict as JSON. Call this to get deterministic, citable evidence about " +
			"the host's CPU, memory, disk, network, services, and more — before diagnosing " +
			"an incident or proposing a fix. The output is the same as `dsd health --json`; " +
			"the schema is stable (dsd-output.json 1.x). This tool is read-only and makes " +
			"no changes to the host.",
	}, toolHealth)

	mcp.AddTool(srv, &mcp.Tool{
		Name: "dsd_capture",
		Description: "Record a raw capture bundle of this host's system inputs to a file. " +
			"The bundle can later be replayed offline with dsd_replay or compared with " +
			"dsd_diff. Use this to preserve the current state before a change, or to " +
			"collect a snapshot for offline diagnosis without needing access to the host " +
			"again. Pass sanitize=true to redact credentials before the file is written.",
	}, toolCapture)

	mcp.AddTool(srv, &mcp.Tool{
		Name: "dsd_replay",
		Description: "Replay a raw capture bundle recorded by dsd_capture (or `dsd capture --raw`) " +
			"and return the health verdict as JSON — without touching the original host. " +
			"Use this to diagnose a customer-supplied bundle, or to compare a captured " +
			"state against a current run with dsd_diff. The output shape is identical to " +
			"dsd_health.",
	}, toolReplay)

	mcp.AddTool(srv, &mcp.Tool{
		Name: "dsd_diff",
		Description: "Diff two capture bundles and return the per-check status transitions " +
			"as a JSON array. Argument order follows diff convention: baseline (before) " +
			"first, current (after) second. Use this to explain what changed between a " +
			"healthy state and a broken one, or to verify that a change had the intended " +
			"effect. Each entry has: name, before, after, status_change, changed, improved.",
	}, toolDiff)

	return srv.Run(context.Background(), &mcp.StdioTransport{})
}
