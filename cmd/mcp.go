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
	"runtime"
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
	mcpCmd.Hidden = true // hidden until end-to-end validated with a real MCP client
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
}

type mcpReplayInput struct {
	BundlePath string `json:"bundle_path" jsonschema:"path to a bundle created with dsd_capture or dsd capture --raw"`
}

type mcpDiffInput struct {
	BaselinePath string `json:"baseline_path" jsonschema:"path to the baseline (before) bundle"`
	CurrentPath  string `json:"current_path"  jsonschema:"path to the current (after) bundle"`
}

// ── tool handlers ──────────────────────────────────────────────────────────

// toolHealth runs the full health pipeline and returns the JSON verdict.
// Equivalent to `dsd health --json [--deep] [--cve]`.
func toolHealth(_ context.Context, _ *mcp.CallToolRequest, in mcpHealthInput) (
	*mcp.CallToolResult, any, error,
) {
	ctx := context.Background()
	ctrCtx := collectors.ContainerContextViaSource()
	cloudEnv := collectors.CloudEnvironmentViaSource()
	profile := collectors.ProfileViaSource()

	results, insights, _, _ := runHealthOnce(ctx, ctrCtx, cloudEnv, profile,
		output.ModePlain, healthRunOpts{IncludeDeep: in.Deep, IncludeCVE: in.CVE, Terse: !in.Deep}, nil)

	data, err := render.RenderJSON(results, insights)
	if err != nil {
		return nil, nil, fmt.Errorf("dsd_health: marshalling result: %w", err)
	}
	return &mcp.CallToolResult{
		Content: []mcp.Content{&mcp.TextContent{Text: string(data)}},
	}, nil, nil
}

// toolCapture records a raw bundle, writing it to in.OutPath.
// Equivalent to `dsd capture --raw [--sanitize] [--identifiers] --out <path>`.
func toolCapture(_ context.Context, _ *mcp.CallToolRequest, in mcpCaptureInput) (
	*mcp.CallToolResult, mcpCaptureOutput, error,
) {
	if in.OutPath == "" {
		return nil, mcpCaptureOutput{}, fmt.Errorf("dsd_capture: out_path is required")
	}
	if in.Identifiers {
		in.Sanitize = true
	}

	ctx := context.Background()
	ctrCtx := platform.DetectContainerContext()
	cloudEnv := platform.DetectCloudEnvironment()
	profile := platform.Detect()

	rec := source.NewRecorder(collectors.ActiveSource())
	prev := collectors.SetSource(rec)
	defer collectors.SetSource(prev)

	gpu := detectGPUPresence()
	results, insights, _, _ := runHealthOnce(ctx, ctrCtx, cloudEnv, profile,
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

	if in.Sanitize {
		b.Sanitize(source.SanitizeOptions{Identifiers: in.Identifiers})
	}
	if err := b.SaveTarball(in.OutPath); err != nil {
		return nil, mcpCaptureOutput{}, fmt.Errorf("dsd_capture: writing bundle: %w", err)
	}

	fi, err := os.Stat(in.OutPath)
	var sz int64
	if err == nil {
		sz = fi.Size()
	}
	return nil, mcpCaptureOutput{
		BundlePath: in.OutPath,
		Host:       host,
		CapturedAt: b.Manifest.Created,
		Bytes:      sz,
	}, nil
}

// toolReplay replays a bundle and returns the JSON health verdict for the
// captured host. Equivalent to `dsd replay <bundle> --json`.
func toolReplay(_ context.Context, _ *mcp.CallToolRequest, in mcpReplayInput) (
	*mcp.CallToolResult, any, error,
) {
	if in.BundlePath == "" {
		return nil, nil, fmt.Errorf("dsd_replay: bundle_path is required")
	}
	b, err := loadBundle(in.BundlePath)
	if err != nil {
		return nil, nil, fmt.Errorf("dsd_replay: loading bundle: %w", err)
	}
	results, insights, _ := replayBundle(b, false, false, false, false)
	data, err := render.RenderJSON(results, insights)
	if err != nil {
		return nil, nil, fmt.Errorf("dsd_replay: marshalling result: %w", err)
	}
	return &mcp.CallToolResult{
		Content: []mcp.Content{&mcp.TextContent{Text: string(data)}},
	}, nil, nil
}

// toolDiff diffs two capture bundles and returns the per-check status
// transitions as a JSON array. Equivalent to `dsd diff <baseline> <current> --json`.
func toolDiff(_ context.Context, _ *mcp.CallToolRequest, in mcpDiffInput) (
	*mcp.CallToolResult, any, error,
) {
	if in.BaselinePath == "" || in.CurrentPath == "" {
		return nil, nil, fmt.Errorf("dsd_diff: baseline_path and current_path are required")
	}
	base, err := loadBundle(in.BaselinePath)
	if err != nil {
		return nil, nil, fmt.Errorf("dsd_diff: loading baseline: %w", err)
	}
	current, err := loadBundle(in.CurrentPath)
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
