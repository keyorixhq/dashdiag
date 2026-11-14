# NET1 — fuzzing pro-bing / go-sdk (MCP) / cobra+viper / go-qrcode as DashDiag calls them

Branch `fuzz/net-cli-mcp` (from origin/main 096ef46a). No production code changed.
Status: targets committed and red-proven; fuzz campaign IN PROGRESS (see §5).

## 0. Readings taken (no one to ask)

- This repo has no CLAUDE.md, INVARIANTS.md / INVARIANTS.d, changelog.d or
  scripts/fuzzing/targets.d (those are Keyorix conventions). Fuzz targets here
  are discovered automatically by `scripts/fuzz-discover.sh` (guarded by
  `fuzz_coverage_test.go`), so no targets.d conf, no changelog fragment and no
  INVARIANTS.d entry were written: the mechanisms do not exist. The report
  sits at the repo root like the sibling `d1-REPORT.md` convention.
- "Promote a target" = commit a discovered `FuzzXxx` with seeds.
- Reproducers that FAIL on the current tree (the red half of a red/green
  proof) are committed but gated behind `DSD_NET1_REPRO=1`, so CI stays green;
  their green halves always run.
- go-modern-guidelines was run (network OK); its list is generic per file. One
  deliberate deviation: the MCP decode differential uses `encoding/json` v1,
  not json/v2, because v1 is the reference semantics the SDK's segmentio
  decoder claims; json/v2 differs by design (case-sensitive, rejects duplicate
  keys) and would yield only expected differences.
- `golang.org/x/net` and `github.com/spf13/pflag` are now imported directly by
  test files but stay `// indirect` in go.mod; `go mod tidy` would flip the
  marker. Left unchanged (no tidy check in Makefile/CI; go.mod is not touched
  by this branch). go.work.sum was modified by `go run` of the guidelines tool
  and is not committed.
- No QR decoder exists in the offline module cache (searched for gozxing,
  tuotoo/qrcode, liyue201/goqr, rsc.io/qr): the harness carries its own.

## 1. Live callers and who controls the bytes

| Library | DashDiag call site | Live caller chain | Bytes controlled by | Reachable today |
|---|---|---|---|---|
| pro-bing v0.9.1 | `internal/collectors/network_quick.go` `tryOnePing` → `goping.NewPinger(host)`, `Run`, `Statistics()` (also `network_deep.go`) | `dsd health` → network collector → `runConnectivityProbes` → `pingRTT` (gateway IP, `8.8.8.8`) | ICMP echo replies: the ping target (default gateway — e.g. a hotel/office router — and 8.8.8.8) and anything on path; both see pro-bing's tracker UUID and send timestamp in the request | macOS: always (pro-bing is the primary path). Linux: only when `/bin/ping` fails (sysPing first). Requires `--network`/DSD_ALLOW_NETWORK? No: connectivity probes run by default unless DSD_OFFLINE. |
| go-sdk v1.8.0 | `cmd/mcp.go` `runMCP` (`mcp.NewServer`, `mcp.AddTool` ×5, `StdioTransport`) | `dsd mcp` (registered by `claude mcp add dsd -- dsd mcp`) | JSON-RPC frames: the MCP client (trusted local process). Tool **arguments**: LLM-generated, prompt-injectable (THREAT_MODEL §5) | Yes, whenever an agent runs `dsd mcp` |
| cobra v1.10.2 / pflag v1.0.10 | `cmd/root.go` `Execute` → `rootCmd.Execute()`; every `cmd/*.go` flag definition | every `dsd` invocation | argv: operator, scripts/CI wrappers that splice values (endpoints, paths) | Yes |
| viper v1.21.0 (+yaml.v3, mapstructure) | `internal/config/config.go` `Load` | `internal/collectors/services.go` `Collect` → `config.Load("")` (implicit `$HOME/.dsd.yaml`); no CLI `--config` exists | whoever can write `$HOME/.dsd.yaml`; under `sudo -E` a preserved unprivileged $HOME (root-owner gate) | Yes (Services); Thresholds/Logs/Security are parsed and validated but **not consumed anywhere** |
| go-qrcode (2020-06-17) | `internal/output/qr.go` `PrintQRCode` | `cmd/health.go` `printHealthFooter` with `--qr` | the share URL — documented as a future share-server response | **No**: `shareURL := ""` (stub), `PrintQRCode` returns before encoding |

## 2. Targets (all promoted, all auto-discovered)

| Target | Package | Oracle kind |
|---|---|---|
| `FuzzMCPJSONRPCToolArgs` | cmd | differential (SDK segmentio decode vs encoding/json), framing, liveness/bounded work, path-policy |
| `FuzzSafeBundlePathContainment` | cmd | differential (filepath.Rel containment), idempotence + rel/abs metamorphic |
| `FuzzProBingReplyAccounting` | internal/collectors | model differential (independent ICMP decoder + accounting model), exact stats recomputation, RTT = receive − payload ts |
| `FuzzLoadPrecedenceMetamorphic` | internal/config | precedence model, rendering metamorphic (block / reversed / flow), env independence, unsafe-file gate, secret echo |
| `FuzzCobraArgvMetamorphic` | cmd | argv metamorphic over dsd's real command tree (=/space, order, shorthand, hex, persistent-first, `--`), secret echo |
| `FuzzQRCodeRoundTrip` | internal/output | round-trip through an independent decoder (library + real PrintQRCode art), ISO conformance (BCH, RS syndromes, quiet zone), bounded size/work, idempotence |

### What each oracle does NOT verify

(Verbatim from each target's doc comment.)

- **FuzzMCPJSONRPCToolArgs**: the real tool bodies (health pipeline, bundle
  I/O) — handlers stop after argument decoding and safeBundlePath; output
  schema validation of real tool results; symlink resolution (path oracle is
  lexical — see NET1-F1); the stdio MaxLineLength cap (>1 MiB frames); several
  concurrent in-flight calls. Raw-frame mode accepts the SDK closing the
  session on an undecodable frame (bounded, not a hang; raw frames come from
  the trusted client) — a hang is still a failure in every mode.
- **FuzzSafeBundlePathContainment**: symlinks (NET1-F1); case-insensitive
  filesystems; over-rejection ("a..b" is refused — fail-closed); Windows
  volume/UNC semantics.
- **FuzzProBingReplyAccounting**: the kernel/socket layer (ListenPacket, ID
  filter, Source binding); IPv6; Count-based early stop (Count=-1, a fence
  reply ends the run); seq wrap past 65535; plausibility of an RTT derived
  from a forged payload timestamp (NET1-F3, by design); forged timestamps are
  bounded to now ± 2^61 ns in the fuzz fixture because beyond that the
  already-reproduced NET1-F2 overflow is all the fuzzer would find; forged
  sequence numbers are restricted to already-sent or unreachable (≥60000)
  values because a not-yet-sent seq has a racy outcome; DashDiag's sysPing path.
- **FuzzLoadPrecedenceMetamorphic**: Security defaults when the file omits the
  section (NET1-F4); unknown keys that alias a known key via
  strings.EqualFold (mapstructure) or viper's "." delimiter (documented viper
  behaviour, excluded by the generator); type-mismatched scalars (weak
  decoding); the root-owner gate and symlink refusal (root-only / unit-tested
  elsewhere); the explicit-path branch (no live caller).
- **FuzzCobraArgvMetamorphic**: command bodies (RunE replaced by a recorder);
  PersistentPreRun side effects; flag types outside the cloned set; repeated
  occurrences of one flag; -h/--help and completion; echo of a value inside
  the very token that failed (pflag quotes the failing token by design).
- **FuzzQRCodeRoundTrip**: decoder covers versions 1-10 only (ISO table typed
  in, self-checked by RS syndromes and module count); scanning robustness;
  Kanji/ECI; mask penalty optimality; ToSmallString/PNG/Image. Inputs that
  sanitize to "" are skipped in the PrintQRCode leg (NET1-F5, reproduced
  separately).

## 3. Red/green proof per oracle

All plants were made in a scratch worktree (`.scratch/plant`, libraries via
`go work vendor` into its own vendor/), never on the branch. "Fires" = the
committed target, unchanged, fails; the unmodified tree passes the same run.

| Plant | Where | Oracle that fired |
|---|---|---|
| P1 `HasPrefix(abs, cwd)` without separator | cmd/mcp.go safeBundlePath | FuzzSafeBundlePathContainment containment (seed `cwd-sibling/x`); FuzzMCPJSONRPCToolArgs path policy (plant-only seed) |
| P2 `bytes.ToUpper(input)` before typed decode | go-sdk mcp/server.go | MCP decode differential |
| P3 10 s sleep in tool dispatch | go-sdk mcp/server.go | MCP liveness/bounded work |
| P3b extra non-JSON line on error responses | go-sdk mcp/transport.go | MCP framing |
| P4a seq not removed from awaiting set | pro-bing ping.go processPacket | accounting (recv/dups vs model) |
| P4b RTT + 1 s | pro-bing processPacket | RTT = receive − payload timestamp |
| P4c Welford divides by n+1 | pro-bing updateStatistics | AvgRtt vs exact mean |
| P4d loss subtracts duplicates | pro-bing Statistics | PacketLoss recomputation / [0,100] |
| P5a drop SetDefault(disk_warn_pct) | config.go | precedence model |
| P5b `v.AutomaticEnv()` | config.go | environment independence |
| P5c host in port-range error | config.go Validate | secret echo (found by fuzzing in 0.05 s) |
| P5d group-writable trusted | config.go implicitConfigSafe | unsafe-file gate |
| P5e flow-style file decoded differently | config.go Load | rendering metamorphic |
| P6a `TrimSpace` on `--f v` values | pflag parseLongArg | argv metamorphic (eq vs space) |
| P6b first arg after `--` dropped | pflag parseArgs | argv metamorphic (eq vs dashdash) |
| P6c argv appended to the printed error | cobra ExecuteC | secret echo |
| P7a PrintQRCode encodes a truncated url | internal/output/qr.go | round-trip (PrintQRCode leg) |
| P7b one RS EC byte flipped | go-qrcode reedsolomon | conformance (non-zero syndromes) |
| P7c second Bitmap() flips a module | go-qrcode Bitmap | idempotence — **did not fire at first**: the oracle compared aliased storage. Harness fixed (deep copy, commit "deep-copy the first QR bitmap"), plant then fired |
| P7d version ≥27 forced for >90 bytes | go-qrcode New | bounded size |

Not individually planted (covered only by their family's plant): QR
format/version BCH sub-checks, QR 2 s work cap, MCP dispatch-name check,
pro-bing PacketsSent and Min/Max sub-checks, cobra positionals check.

## 4. Findings

| ID | Class | Summary | Reproducer |
|---|---|---|---|
| NET1-F1 | CANDIDATE (security) | `safeBundlePath` is lexical: a directory symlink inside CWD pointing outside lets `dsd_capture` write (and `dsd_replay`/`dsd_diff`/`dsd_share` read) outside CWD; O_NOFOLLOW only covers the last component | `cmd/mcp_symlink_repro_test.go` (`DSD_NET1_REPRO=1`) |
| NET1-F2 | DEFECT (upstream pro-bing) | Welford `delta := pkt.Rtt - p.avgRtt` overflows int64 when forged RTTs differ by >292 years: AvgRtt gets the wrong sign | `internal/collectors/probing_reply_repro_test.go` TestReproProBingAvgRttOverflow |
| NET1-F3 | DEFECT (DashDiag) / HARDENING | one forged echo reply with a future payload timestamp gives a negative RTT; DashDiag's `< 0` "unreachable" sentinel collides with it: a reachable gateway reads as "not responding" (or CRIT "host appears offline" if the internet probe is forged too) and the packet-loss check is skipped | TestReproProBingNegativeRTT |
| NET1-F4 | DEFECT (latent) | any `$HOME/.dsd.yaml` zeroes every Security default (AllowedPorts empty, SSH thresholds 0) — only thresholds/logs get SetDefault. No live consumer reads Security (or Thresholds) today | `internal/config/load_precedence_fuzz_test.go` TestReproLoadDropsSecurityDefaults |
| NET1-F5 | DEFECT (cosmetic, unreachable) | `PrintQRCode` checks `url == ""` before sanitizing; an all-control url prints a dangling `QR: ` line | `internal/output/qr_roundtrip_fuzz_test.go` TestReproPrintQRCodeAllControlURL |
| NET1-E1 | EXPECTED-DIFFERENCE | go-sdk closes the session on a frame that is not JSON-RPC 2.0 (`"jsonrpc":"1.0"`, non-UTF-8) instead of answering -32700 | seeds #13/#15 of FuzzMCPJSONRPCToolArgs |
| NET1-E2 | EXPECTED-DIFFERENCE | go-qrcode rejects empty content | FuzzQRCodeRoundTrip corpus 755b0c52 |
| NET1-A1..A4 | ARTIFACT (harness, fixed) | MCP raw-frame close premise; pro-bing racy forged seq (corpus a4c03a4c); config block renderer dropped scalar list items (corpus fdfae522); cobra empty string rendered as bare flag | committed as regression seeds |

Every red reproducer was replayed 3× (all 3 red, all greens pass).

(Details, reachability traces, upstream reproducer and issue-ready proposals: §6–§7.)

## 5. Fuzz campaign

IN PROGRESS — filled in as chunks complete.
