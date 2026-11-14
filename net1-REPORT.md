# NET1 — fuzzing pro-bing / go-sdk (MCP) / cobra+viper / go-qrcode as DashDiag calls them

Branch `fuzz/net-cli-mcp` (from origin/main 096ef46a). No production code changed.
Status: DONE. Six targets committed and red-proven; ≈140 min of fuzzing (§5); final checks in §9.

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
| pro-bing v0.9.1 | `internal/collectors/network_quick.go` `tryOnePing` → `goping.NewPinger(host)`, `Run`, `Statistics()` (also `network_deep.go`) | `dsd health` → network collector → `runConnectivityProbes` → `pingRTT` (gateway IP, `8.8.8.8`) | ICMP echo replies: the ping target (default gateway — e.g. a hotel/office router — and 8.8.8.8) and anything on path; both see pro-bing's tracker UUID and send timestamp in the request | Only with `--network` or `DSD_ALLOW_NETWORK=1` (network_quick.go:180 gate; off by default, and skipped under replay). Then: macOS always (pro-bing is the primary path); Linux only when `/bin/ping` fails (sysPing first). |
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
| NET1-F6 | DEFECT (upstream go-sdk) | the stdio/IO transport decodes a JSON stream instead of newline-delimited frames: a one-line truncated frame swallows the following request, which is never answered | `cmd/mcp_framing_repro_test.go` |
| NET1-E1 | EXPECTED-DIFFERENCE | go-sdk closes the session on a frame that is not JSON-RPC 2.0 (`"jsonrpc":"1.0"`, non-UTF-8) instead of answering -32700 | seeds #13/#15 of FuzzMCPJSONRPCToolArgs |
| NET1-E2 | EXPECTED-DIFFERENCE | go-qrcode rejects empty content | FuzzQRCodeRoundTrip corpus 755b0c52 |
| NET1-A1..A7 | ARTIFACT (harness, fixed) | see §6 "Expected differences and artifacts" | regression seeds committed |

Every red reproducer was replayed 3× (all 3 red, all greens pass).

(Details, reachability traces, upstream reproducer and issue-ready proposals: §6–§7.)

## 5. Fuzz campaign

Foreground chunks, `GOMAXPROCS=3 nice -n 10 go test -fuzz … -fuzztime 510s
-parallel 2`, macOS arm64 laptop, go1.27.3. Real wall-clock time; logs in
`.scratch/fz_*.txt` (not committed). Loopback listeners were never needed:
MCP runs over io.Pipe, pro-bing over a fake packetConn.

| Target | Chunks (real time) | Total | Execs (clean chunks) | Hits → triage |
|---|---|---|---|---|
| FuzzProBingReplyAccounting | 8m30 + 8m30 + 8m31 (+1m45 smoke) | 25.5 min (+1.75) | 440k + 604k + 371k | smoke: racy forged seq (A2, fixture fixed), AvgRtt overflow (F2, reproduced, fixture bounded) |
| FuzzMCPJSONRPCToolArgs | 16 s + 8m31 + 8m31 + 8m31 | 25.8 min | 437k + 381k + 598k | truncated frame swallows the next (F6, reproduced, quarantined) |
| FuzzSafeBundlePathContainment | 8m31 + 8m30 | 17.0 min | 1.89M + 3.10M | none |
| FuzzLoadPrecedenceMetamorphic | 1m41 + 8m31 + 2m31 + 8m30 (+2 min smoke) | 21.2 min (+2) | 375k + 480k | smoke: block renderer bug (A3); DEL/C1 in YAML scalar (A5, harness); host substring inside echoed name (A6, harness) |
| FuzzCobraArgvMetamorphic | 8m30 + 8m30 + 8m30 (+1 min smoke) | 25.5 min (+1) | 356k + 395k + 399k | smoke: empty value as bare flag (A4, harness) |
| FuzzQRCodeRoundTrip | 8m31 + 8m31 + 8m31 (+1.2 min smoke) | 25.5 min (+1.2) | 185k + 88k + 62k | smoke: empty content (E2), all-control url (F5, reproduced) |
| **Total** | | **≈140.5 min** (+≈7 smoke) | | round 3 (after the final checks): no new hits |

Every hit was minimised by the Go fuzzer, replayed 3× (`-count=3`), and kept
as a committed regression seed when it was a harness artifact or an
expected difference (the seed now passes).

## 6. Findings in detail, with reachability

### NET1-F1 — CANDIDATE: directory-symlink escape of the MCP CWD constraint

- **Trace:** MCP client → go-sdk tools/call → `toolCapture` (cmd/mcp.go:269)
  → `safeBundlePath(in.OutPath)` (lexical Clean + `..` + HasPrefix(cwd)) →
  `b.SaveTarball(outPath)` → `tarGzDir` → `os.OpenFile(dst,
  O_WRONLY|O_CREATE|O_TRUNC|O_NOFOLLOW)` (internal/source/tarball.go:83).
  O_NOFOLLOW guards only the final component. Read side: `toolReplay`,
  `toolDiff`, `toolShare` (from_path) → same check → `loadBundle`.
- **Who controls it:** out_path is LLM-generated (THREAT_MODEL §5's own
  premise). The symlink must already exist under CWD — e.g. shipped inside a
  cloned repository (git stores symlinks) that also carries the injected text.
- **Impact:** truncate-and-overwrite of any file the dsd user can write,
  outside CWD, with a gzip tarball (content not attacker-chosen), and reads of
  files outside CWD. This is exactly what THREAT_MODEL §5 says the CWD
  constraint prevents; §5's residual-gaps list does not mention symlinks.
- **Proof:** `TestReproSafeBundlePathDirSymlinkEscape` (red ×3: `toolCapture`
  wrote 675-677 bytes into the outside dir); `…_ProposedFixGreen` (passes).
- **Why CANDIDATE, not VULNERABILITY:** not exercised end to end with a real
  agent and a real malicious repository; needs a pre-planted symlink.
- **Issue-ready proposal:** open the CWD once at `dsd mcp` start with
  `os.OpenRoot(cwd)` (Go ≥1.24) and do every bundle read/write through the
  `*os.Root` (it refuses symlink and `..` escapes at open time, TOCTOU-safe);
  short of that, `filepath.EvalSymlinks` on the parent directory and re-check
  containment on the real path (the harness's `safeBundlePathProposedFix`),
  and add the symlink case to THREAT_MODEL §5 residual gaps.

### NET1-F2 — DEFECT (upstream pro-bing v0.9.1): AvgRtt int64 overflow

- **Trace:** `tryOnePing` (network_quick.go:516-554) → `p.Run()` →
  processPacket → updateStatistics → `stats.AvgRtt` → `avgMs`. Bytes: echo
  replies from the ping target / on-path host, which see the request payload.
- **Upstream-ready reproducer** (internal test in package `probing`):

  ```go
  func TestUpdateStatisticsAvgRttOverflow(t *testing.T) {
  	p := New("127.0.0.1")
  	const year = 365 * 24 * time.Hour
  	p.updateStatistics(&Packet{Rtt: -100 * year})
  	p.updateStatistics(&Packet{Rtt: 200 * year})
  	if got, want := p.Statistics().AvgRtt, 50*year; got != want {
  		t.Fatalf("AvgRtt = %v, want %v", got, want)
  	}
  }
  ```

  Version: github.com/prometheus-community/pro-bing v0.9.1, Go 1.27.
  Expected: 438000h (50 years). Actual (validated in a scratch copy via
  linkname to updateStatistics): `AvgRtt = -2124047h47m16.854775808s` —
  `delta := pkt.Rtt - p.avgRtt` (ping.go:358) is 300 years in ns, beyond
  MaxInt64, and wraps. Both RTTs are reachable because Rtt is
  `receivedAt.Sub(payloadTimestamp)` with the timestamp taken from the reply.
  DashDiag-side harness: `TestReproProBingAvgRttOverflow` (red ×3: AvgRtt
  −1416031h vs exact mean +1051200000002802333 ns).
- **Suggested upstream fix:** accumulate in float64 or big-int, or saturate.

### NET1-F3 — DEFECT (DashDiag) / HARDENING: forged RTT collides with the unreachable sentinel

- **Trace:** forged echo reply (future payload timestamp) → pro-bing Rtt < 0
  → `tryOnePing` returns `avgMs < 0, loss 0, ok=true` → `GatewayPingMs` /
  `InternetPingMs` → `internal/analysis/heuristics_network.go:520-541`, where
  `< 0` means "unreachable": a reachable gateway becomes INFO "gateway not
  responding to probes" (or CRIT "host appears offline" if both are forged),
  latency WARN/CRIT is skipped, and the packet-loss check (`GatewayPingMs >=
  0`) is skipped.
- **Proof:** `TestReproProBingNegativeRTT` (red ×3: −4996…−4999.9 ms from one
  forged reply); green with an honest reply.
- **Severity:** an on-path party can already drop packets; this lets it
  produce a *specific* misleading verdict and hide real loss. Not security
  beyond that. pro-bing trusting the echoed timestamp is by design (iputils
  ping does the same but warns on negative time).
- **Proposal:** in `tryOnePing`, treat `AvgRtt < 0` (or `> Timeout`) as an
  implausible measurement (fall back to TCP / report "measurement invalid"),
  and stop overloading `< 0` as "unreachable" in NetworkInfo (explicit
  reachable flag).

### NET1-F4 — DEFECT (latent): any config file zeroes the Security defaults

- **Trace:** `services.go:25` `config.Load("")` → `v.Unmarshal(&cfg)` into a
  zero Config; SetDefault exists only for thresholds/logs (config.go:194-210).
  Security (and Thresholds) have **no consumer** today — only `cfg.Services`
  is read — so no live verdict changes.
- **Proof:** `TestReproLoadDropsSecurityDefaults` (red ×3: AllowedPorts [],
  SSH warn/crit 0/0 vs 22,80,…/20/50); green with no file.
- **Proposal:** `cfg := defaults` (with a cloned AllowedPorts) then
  `v.Unmarshal(&cfg)` so absent keys keep defaults, or SetDefault the
  security keys; decide whether Thresholds/Security should exist at all while
  nothing consumes them (users editing them get no effect, silently).

### NET1-F5 — DEFECT (cosmetic, unreachable today)

`PrintQRCode` checks `url == ""` before `SanitizeControl`; an all-control url
prints `QR: ` and nothing else. Unreachable: the only caller passes "".
Proposal: sanitize first, then the empty check. Proof:
`TestReproPrintQRCodeAllControlURL` (red ×3), green with "".

### NET1-F6 — DEFECT (upstream go-sdk v1.8.0): stdio frames are not newline-delimited

- **Trace:** `runMCP` → `srv.Run(ctx, &mcp.StdioTransport{})` →
  `newIOConnLimited` (mcp/transport.go:500-554) → `json.NewDecoder(reader)`.
  A line that is incomplete JSON is not rejected at its newline; the decoder
  keeps reading and absorbs the following frame(s). Any decode error is also
  terminal for the session (NET1-E1).
- **Who controls it:** only the MCP client (trusted). The LLM cannot emit a
  raw frame; Claude Code/Cursor serialise complete lines. Not a security
  issue for dsd; a robustness/spec-conformance issue upstream.
- **Upstream-ready reproducer:**

  ```go
  func TestIOTransportTruncatedLineSwallowsNext(t *testing.T) {
  	inR, inW := io.Pipe()
  	outR, outW := io.Pipe()
  	srv := mcp.NewServer(&mcp.Implementation{Name: "s", Version: "0"}, nil)
  	ss, err := srv.Connect(context.Background(), &mcp.IOTransport{Reader: inR, Writer: outW}, nil)
  	if err != nil {
  		t.Fatal(err)
  	}
  	defer ss.Close()
  	go io.WriteString(inW, `{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"c","version":"0"}}}`+"\n"+
  		`{"jsonrpc":"2.0","method":"notifications/initialized","params":{}}`+"\n"+
  		`{"":`+"\n"+
  		`{"jsonrpc":"2.0","id":2,"method":"ping"}`+"\n")
  	got := make(chan string, 8)
  	go func() {
  		sc := bufio.NewScanner(outR)
  		for sc.Scan() {
  			got <- sc.Text()
  		}
  		close(got)
  	}()
  	timeout := time.After(3 * time.Second)
  	for {
  		select {
  		case line, ok := <-got:
  			if !ok || strings.Contains(line, `"id":2`) {
  				return // answered, or the session ended: both acceptable
  			}
  		case <-timeout:
  			t.Fatal("line 3 was not rejected on its own; ping (id 2) swallowed")
  		}
  	}
  }
  ```

  Expected (MCP stdio spec: newline-delimited messages): line 3 is rejected
  by itself (parse error or session end) and id 2 is answered or the session
  ends. Actual (this exact test run in a scratch copy against v1.8.0):
  `line 3 was not rejected on its own; ping (id 2) swallowed` after 3 s. DashDiag-side proof: `cmd/mcp_framing_repro_test.go` (red ×3,
  green ×3).
- **Suggested upstream fix:** split on '\n' first (bufio.Reader.ReadSlice
  with the existing frame limit), then decode each line on its own.

### Expected differences and artifacts

- **NET1-E1:** go-sdk ends the session on a frame that is not JSON-RPC 2.0
  instead of answering −32700 (seen as `io: read/write on closed pipe`).
  Bounded; trusted client only.
- **NET1-E2:** go-qrcode refuses empty content.
- **Harness artifacts (all fixed in the harness, never by loosening an
  assertion):** A1 MCP raw-frame premise (closing ≠ hanging); A2 pro-bing
  forged seq not yet sent (racy); A3 config block renderer dropped scalar list
  items; A4 cobra empty string value rendered as a bare flag; A5 DEL/C1 left
  raw in YAML by json.Marshal; A6 host-substring heuristic matched inside the
  echoed service name; A7 QR idempotence compared aliased storage (found by
  the red-proof plant, not by fuzzing).

### Findings table (summary)

| ID | Class | Library | Live caller | Reproducer |
|---|---|---|---|---|
| F1 | CANDIDATE | DashDiag (cmd/mcp.go) | dsd mcp → toolCapture/Replay/Diff/Share | cmd/mcp_symlink_repro_test.go |
| F2 | DEFECT (upstream) | pro-bing v0.9.1 | dsd health --network (macOS; Linux fallback) | internal/collectors/probing_reply_repro_test.go |
| F3 | DEFECT / HARDENING | DashDiag + pro-bing | same | internal/collectors/probing_reply_repro_test.go |
| F4 | DEFECT (latent) | DashDiag (config) | services collector (Security unused) | internal/config/load_precedence_fuzz_test.go |
| F5 | DEFECT (cosmetic) | DashDiag (output) | none today (shareURL stub) | internal/output/qr_roundtrip_fuzz_test.go |
| F6 | DEFECT (upstream) | go-sdk v1.8.0 | dsd mcp (trusted client only) | cmd/mcp_framing_repro_test.go |
| E1, E2 | EXPECTED-DIFFERENCE | go-sdk, go-qrcode | — | corpus seeds |
| A1–A7 | ARTIFACT | harness | — | fixed, seeds kept |

No VULNERABILITY is claimed. Nothing was reported upstream or pushed.

Run all red halves: `DSD_NET1_REPRO=1 go test ./cmd ./internal/collectors
./internal/config ./internal/output -run 'TestRepro' -count=3`.

## 7. Issue-ready proposals (no production change made)

1. **cmd/mcp.go — confine MCP bundle I/O with os.Root** (F1). Title: "dsd mcp:
   CWD constraint on path arguments is bypassable through a directory
   symlink". Body: trace + reproducer above; fix via `os.OpenRoot`, or
   EvalSymlinks + re-check; THREAT_MODEL §5 residual gap.
2. **network_quick.go — reject implausible RTTs; stop using < 0 as
   "unreachable"** (F3, mitigates F2 for DashDiag).
3. **pro-bing upstream — overflow-safe running mean** (F2) with the test above.
4. **go-sdk upstream — line-delimited stdio framing** (F6) with the test above.
5. **config.go — keep defaults for keys the file omits** (F4); and decide on
   the unconsumed Thresholds/Security sections.
6. **qr.go — sanitize before the empty check** (F5).
7. **go.mod hygiene** — `golang.org/x/net` and `github.com/spf13/pflag` are
   now direct test imports; run `go mod tidy` in a deps PR.

## 8. Talk material

DashDiag's five network/CLI dependencies were fuzzed the way DashDiag
actually calls them: the real pro-bing receive path through a fake socket,
the real MCP SDK over an in-memory pipe, dsd's own command tree and config
path, and the real QR printer decoded by a decoder written for the job. Every
oracle is a round-trip, a differential against an independent model, or a
metamorphic relation, and each one was watched failing on a planted bug first
— one of them (QR idempotence) turned out to be vacuous until the plant
exposed it. The fuzzers found an int64 overflow in pro-bing's running mean, a
JSON-stream framing flaw in the MCP SDK where one truncated line swallows the
next request, and harness bugs that were fixed in the harness instead of
loosening assertions. Reading the callers mattered as much as fuzzing:
a forged ping reply can turn a reachable gateway into "host offline" because
DashDiag uses negative milliseconds as its unreachable sentinel, and a
directory symlink walks straight through the lexical CWD check meant to stop
prompt-injected MCP paths. Nothing here is claimed as a vulnerability; the one
security candidate comes with a red/green proof and a concrete os.Root fix.

## 9. Final checks (at the branch head)

- `gofmt -l cmd internal/collectors internal/config internal/output`: clean.
- `go vet` on the four touched packages, darwin and `GOOS=linux`: clean.
- `go build ./...`: OK.
- Seed corpus of all six targets + every `TestRepro*` (red halves skip
  without `DSD_NET1_REPRO=1`): `ok` in all four packages.
- Full `go test` of cmd, internal/collectors, internal/config,
  internal/output: `ok` (cmd 92 s).
- `go test -race` on the MCP and pro-bing harness seeds + reproducers: clean.
- `TestFuzzDiscoveryCoversEverySourceFuzzFunc` (scripts/fuzz-discover.sh sees
  every new target): pass.
- `make lint-linux` (golangci-lint in the dashdiag-dev container) was NOT
  run: no new file is `//go:build linux`, and Docker was not used in this
  session; linux was covered by `GOOS=linux go vet` only.
- Scratch plant worktree removed; go.work.sum left untouched; no background
  processes started.
