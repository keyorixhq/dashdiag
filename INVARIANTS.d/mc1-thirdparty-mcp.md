# INVARIANTS — MC1 third-party target: modelcontextprotocol/go-sdk

Target: `cmd` · `FuzzMCPServerHostileJSONRPC`.

Scope: the go-sdk JSON-RPC / transport layer of `dsd mcp` — frame splitting
(newline-delimited JSON, 16 MiB `DefaultMaxLineLength`), JSON-RPC decode, id /
batch handling, schema validation and async dispatch — driven with hostile raw
bytes over an `mcp.IOTransport` (same framing as the production `StdioTransport`).
The five real tool schemas are registered (identical inferred JSON Schemas) with
recording STUB handlers in place of the collector-running bodies, so the run is
deterministic and the dispatch layer carries no disk path.

- **M1 no panic.** The server survives any byte stream without panicking.
- **M2 bounded work.** Feeding one input (handshake + raw, held open for a 5ms
  quiescence so async dispatch flushes, then EOF) stays within the shared
  resource oracle (alloc factor 4096 + time + goroutines). Catches a frame
  decoder that amplifies on a huge line / deep nesting / huge batch, or a hang.
- **M3 terminal-safe output.** Every byte the server writes back is valid UTF-8,
  carries no raw ESC (0x1B) and no C0 control but the `\n` frame delimiter —
  hostile strings echoed through tool args or quoted in errors must be
  JSON-escaped by the SDK's response encoder, never passed through raw.
- **M5 dispatch stays in-schema.** When a tool handler is invoked, the tool name
  is one of the five registered tools.

NOT asserted: the read-only / no-host-write claim (the write-capable handler
dsd_capture is stubbed here and is gated by `safeBundlePath` — DL1 target 2 —
plus `write_capable_callsites_test.go`; a fingerprint oracle here would be
vacuous). Also not covered: safeBundlePath containment, the collector pipeline /
redaction, the SSE/Streamable HTTP transports (dsd runs stdio only), and whether
each malformed argument is rejected for the right reason.

Red/green: planted raw-ESC / raw-C0 / invalid-UTF-8 output each fired M3 (scratch
removed). M2 shares the resource helper proven by the viper target.
