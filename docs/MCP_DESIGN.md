# MCP server design (`dsd mcp`)

Status: **Implemented and shipped** (2026-07-18). Design captured 2026-06-21;
implementation followed in a later session. Register with Claude Code:
`claude mcp add dsd -- dsd mcp`

Scope decided up front (with the founder): the first cut exposes **health +
capture/replay** — the read-only verdict plus the snapshot/compare workflow. No
config generation, no remediation, no AI in the binary (see Non-goals).

---

## Why

The thesis is already recorded in `docs/COMPETITIVE.md` (Agentic-DevOps field
report) and the private ADRs:

- The shared bottleneck in agentic DevOps is **context**. Competitors manufacture
  it by fine-tuning models — unverifiable recall. dsd's `dsd health --json` is the
  opposite: it *generates* deterministic, structured, **citable** evidence.
- "Give the agent the **diagnosis**, not the commands." A coding/ops agent
  (Claude Code, Cursor, an internal agent, or AWS's host-debug agent that already
  takes customer MCP servers as tool extensions) should call one tool and get a
  scored host verdict back — not be handed a shell and told to run `journalctl`.

An MCP server is the literal product expression of that thesis, and a
**distribution** play into a population that already exists (every Claude Code /
Cursor / MCP-client user) at zero marginal install cost — dsd already ships as a
single static binary, so the server is a subcommand, not a new artifact.

This does **not** move dsd up-stack or across the read-only wall. The MCP server
is a transport in front of the *same* collectors → analysis → render pipeline. It
adds reach, not capability.

---

## Non-goals (the walls this design must not breach)

These are load-bearing — they're what makes dsd safe to hand an autonomous agent.

1. **No config generation, ever** (ADR-0006 read-only wall). The server returns
   diagnoses and explanations. It never emits a config, a patch, or a "fixed"
   file. Read-only verdicts forever.
2. **No remediation execution.** No tool mutates host state. The one tool that
   writes to disk (`dsd_capture`) writes a *diagnostic bundle* to a path the
   caller names — it does not touch the system under test.
3. **No AI in the binary** (ADR-0008). The server is plumbing: deterministic Go
   collectors in, structured JSON out. The intelligence lives in the *consuming*
   agent. dsd is the citable context source, not a model.
4. **No new collectors or verdict logic.** The MCP layer is an adapter over the
   existing pipeline. If a verdict is wrong, it's wrong in `dsd health` too — fix
   it there. The MCP server must never grow its own analysis path (that would be a
   second source of truth and a new false-OK surface).

---

## Surface

A new hidden-until-ready subcommand:

```
dsd mcp        # speak MCP over stdio (JSON-RPC 2.0), serving tools below
```

- **Transport: stdio only** for v1 — newline/length-framed JSON-RPC on
  stdin/stdout. This is what Claude Code, Claude Desktop, and Cursor launch and
  manage as a child process; it needs no port, no auth, no network surface. (An
  HTTP/SSE transport is a later option for a remote/hosted server — explicitly out
  of scope here; see Open questions.)
- **Library: the official Go MCP SDK** (`github.com/modelcontextprotocol/go-sdk`,
  maintained with Google) — `mcp.NewServer` + `mcp.AddTool` + `mcp.StdioTransport`,
  with tool input schemas generated from Go structs. Avoids hand-rolling the
  JSON-RPC framing and keeps us on the spec as it evolves. One new dependency;
  CGO-free, so the cross-compile matrix is unaffected.

The subcommand stays hidden from `--help` until the tool surface is validated end
to end against a real MCP client, mirroring the `--share`/`--qr` precedent
(`SHARE_DESIGN.md`).

---

## Tools (v1)

Four tools — the chosen "health + capture/replay" scope. Each is a thin wrapper
over an existing code path; the **output of every tool is the existing
`render.JSONOutput` shape** (or a `DiffEntry` array), so the MCP contract inherits
the frozen `schema/dsd-output.json` 1.x stability promise (`COMPATIBILITY.md`) for
free — no second schema to maintain.

| Tool | Wraps | Input | Output |
|---|---|---|---|
| `dsd_health` | the default health pipeline (`buildHealthCollectors` → `ApplyThresholds` → `render`) | `{ deep?: bool, cve?: bool }` | `JSONOutput` (verdict + checks[] + insights[]) |
| `dsd_capture` | `dsd capture --raw` | `{ out_path: string, sanitize?: bool, identifiers?: bool }` | `{ bundle_path, host, captured_at, bytes }` |
| `dsd_replay` | `dsd replay <bundle>` | `{ bundle_path: string }` | `JSONOutput` for the captured host |
| `dsd_diff` | `dsd diff <baseline> <current>` (`baseline.ComputeDiff`) | `{ baseline_path, current_path }` | `DiffEntry[]` (per-check status transitions) |

Tool descriptions are **prescriptive about *when* to call** (recent-Opus tool
descriptions reward this): e.g. `dsd_health` → "Call this to get a scored
health verdict for the host this server runs on, before diagnosing an incident or
proposing a fix." Each tool's description names the read-only, deterministic
nature so the agent can cite the result as evidence.

Deliberately **excluded from v1** (additive later, demand-gated): per-subsystem
tools (`dsd_net`, `dsd_docker`, `dsd_k8s`, …), `dsd_cve`/`dsd_cis`, `dsd_sanitize`
as its own tool. Starting narrow keeps the tool list legible to the agent and the
review surface small. We `log()`/document what's omitted so "4 tools" doesn't read
as "complete coverage."

---

## Architecture

```
MCP client (Claude Code / Cursor / agent)
        │  JSON-RPC over stdio
        ▼
cmd/mcp.go ── internal/mcp (NEW; thin adapter)
        │         · registers 4 tools, maps args → existing entrypoints
        │         · marshals results through internal/render (JSONOutput / DiffEntry)
        ▼
EXISTING pipeline — UNCHANGED:
  internal/collectors → internal/analysis (ApplyThresholds) → internal/render
  internal/source (Live/Recorder/Replay) for capture/replay/diff
```

- `internal/mcp` holds *only* protocol glue: tool registration, argument structs
  (which generate the input schemas), and calls into the same functions
  `cmd/health.go` / `cmd/capture.go` / `cmd/replay.go` / `cmd/diff.go` already use.
  It produces **no verdicts** of its own.
- Reuse, don't fork: the health tool must call the identical collector registry +
  `ApplyThresholds` path as the CLI, then render via the same `JSONOutput`
  marshaller. A divergence here would recreate the cmd-vs-health tally-drift bug
  class at a new boundary (see the `cmd-verdict-tally-drift` history).
- `dsd_replay`/`dsd_diff` reuse `internal/source` replay wiring as-is, so they
  inherit the hermeticity guarantees from the replay epic.

---

## Security & privilege model

- **Runs with the privileges of the process that launched it.** Same root/non-root
  semantics as the CLI — a non-root MCP server degrades to the same explicit
  "couldn't measure" verdicts (`needs_root:true`, `*_unreadable:true`), never to a
  false OK. The privilege rule in CLAUDE.md ("run privileged collectors as both
  root and non-root") applies to the MCP path too; the validation pass diffs a
  root vs non-root server run.
- **No new network egress.** The server itself opens no sockets; it speaks only to
  its parent over stdio. Any probes are the same ones the collectors already do
  (and are recorded/replayed through `internal/source`).
- **The only write is an explicit capture.** `dsd_capture` writes a bundle to the
  caller-named path; nothing else touches disk. `sanitize`/`identifiers` plumb
  straight through to the existing redaction (see the `capture-sanitize-redaction`
  limits — lookup keys still survive; documented, not re-litigated here).
- **Prompt-injection posture.** The server returns data, never executes
  agent-supplied commands. There is no `bash`-style tool. Tool ARGUMENTS,
  though, are a different story from the transport: `out_path`/`bundle_path`/
  etc. are LLM-generated from context the model has read, which can include
  prompt-injected content the operator never typed — a path argument is only
  as trustworthy as the least trustworthy document the calling agent has
  ingested this session. `safeBundlePath` (cmd/mcp.go) accordingly constrains
  every capture/replay/diff path to resolve under the server's current
  working directory by default, bounding a steered `out_path` to the same
  directory tree the agent's other file tools can already reach, rather than
  treating it as an arbitrary-file-write primitive. `--allow-absolute-paths`
  opts an operator back into the old unconstrained behavior as an explicit,
  human-set startup choice. See `docs/THREAT_MODEL.md`'s "MCP out_path"
  section for the full writeup (found and fixed 2026-09; the earlier revision
  of this bullet claimed the existing replay/capture guards were sufficient
  — they weren't the relevant control for this specific risk).

---

## Distribution / how it's consumed

Single static binary already on every install — no extra artifact. Registration is
one line per client:

- **Claude Code:** `claude mcp add dsd -- dsd mcp` (or a `.mcp.json` entry with
  `command: "dsd", args: ["mcp"]`).
- **Claude Desktop / Cursor:** an `mcpServers` config entry pointing at the `dsd`
  binary with `args: ["mcp"]`.

Because the binary runs locally as a child of the client, it diagnoses the machine
the agent is working on — which is exactly the host whose context the agent lacks.

---

## Dependencies & build impact

- One new module: `github.com/modelcontextprotocol/go-sdk`. CGO-free → the
  `GOOS=linux/darwin × amd64/arm64` matrix and the AppImage/.deb/.rpm packaging are
  unaffected. Verify binary-size delta (single-binary size matters for the SteamOS
  AppImage story); if material, the `mcp` subcommand and SDK can sit behind a build
  tag for size-sensitive targets — decision deferred until measured.
- No change to `schema/dsd-output.json` or the `JSONOutput` struct — the MCP tools
  emit the existing shape, so `schema_sync_test.go` continues to guard it.

---

## Testing

- **Unit:** `internal/mcp` arg-struct → entrypoint mapping; tool result marshals to
  the same `JSONOutput` bytes as `dsd health --json` for the same inputs (golden
  comparison — catches any accidental fork of the render path).
- **Protocol:** a table-driven `initialize` → `tools/list` → `tools/call` exchange
  over an in-memory transport, asserting the 4 tools and their input schemas.
- **End-to-end:** drive the server from a real MCP client (Claude Code) against a
  pve01 guest; confirm `dsd_health` returns the same verdict the CLI does, and
  `dsd_capture` → `dsd_replay` → `dsd_diff` round-trips. Run the client once as
  root and once non-root and diff (privilege rule).
- **Determinism:** two `dsd_replay` calls on one bundle return byte-identical
  non-volatile fields (reuses the double-replay-diff harness).

---

## Open questions (resolve before / during build)

1. **HTTP/SSE transport** for a remote/hosted server — out of scope for v1, but the
   `internal/mcp` tool registration should be transport-agnostic so adding it later
   is wiring, not a rewrite.
2. **Resources vs tools.** MCP also has a `resources` concept (read-only data the
   client can pull). A captured bundle or the last health report could be exposed as
   a resource rather than (or in addition to) a tool. Lean tools-only for v1 —
   agents drive tools more reliably than they pull resources — and revisit if a
   consuming agent wants to browse captures.
3. **Concurrency / long collectors.** Deep health and capture take seconds. Confirm
   the SDK's per-call model + our timeouts surface a clean "still working" rather
   than a client-side timeout; cap and document.
4. **Binary-size gate** (above) — measure, then decide on the build tag.
5. **Surfacing the privilege caveat to the agent.** Should `dsd_health` output
   include an explicit `privileged: bool` / `unmeasured: [...]` summary so the
   consuming agent *cites* "measured unprivileged" rather than silently trusting a
   degraded verdict? Likely yes — it's the honest-context principle applied to the
   agent consumer. Decide during build.
