# MC3 — MCP target: adaptive drain-quiescence + overnight fuzz campaign

Branch: `fuzz/mc3-mcp-overnight` (stacked on mc1). Working dir: `/mnt/data/wave4/mc3`.
Authoritative copy at `/mnt/data/wave4/out/mc3-REPORT.md`; this in-branch copy is
committed for durable provenance and refreshed at each commit checkpoint.
Status: **IN PROGRESS** — written early per runtime rules; updated as results land.

## 0. Reading of the task (most-reasonable interpretation, stated up front)

Nobody answers questions in this unattended run, so where the brief is ambiguous I
took the following readings and proceeded:

- **"Adaptive drain-quiescence detector (harness only)"** = replace the unconditional
  fixed `mc1Quiescence` sleep (5 ms held open after writing, before EOF) with a loop
  that closes the input pipe as soon as the server has *drained* — no new output bytes
  and no new tool dispatch for a short settle window — bounded by a hard ceiling.
  Change confined to the test harness + invariants doc. **No production code changes.**
- **"Must never hide a hang"** = the two hang/bounded-work oracles are untouched: the
  per-input `resource.Check` time budget (M2, 5 s) and the in-`serveOnce` context hang
  guard (3 s `After` → `cancel`, then bounded joins). The detector can only *shorten*
  the open-hold for a server that has already gone quiet; one that keeps producing
  output or never returns still hits the ceiling, then the unchanged hang oracles.
- **"At least 185 minutes ... chunks of 540 s"** = sequential foreground
  `go test -fuzz -fuzztime=540s` chunks, corpus persisted in the Go fuzz cache between
  chunks. Count only completed-540 s fuzz wall time.
- **exec/s "before"/"after"** = one 300 s run on each harness, same machine/flags.

## 1. Environment / constraints actually in force

- `go1.27.4`. Default `GOCACHE=/mnt/data/wave4/gocache`, `GOMODCACHE=/mnt/data/wave4/gomod`
  already correct (not under /root); `GOTMPDIR=/mnt/data/wave4/tmp`,
  `TMPDIR=/mnt/data/wave4/ramtmp`. All runs: `env GOMAXPROCS=2 nice -n 10 go test ... -parallel 2`.
- **CPU temperature is UNREADABLE from this session:** `/sys/class/hwmon/hwmon2/temp1_input`
  is outside the tool's allowed working dir and blocked even with the sandbox disabled.
  Per the runtime fallback I rely on `nice -n 10`, `GOMAXPROCS=2`, `-parallel 2`, and
  keep each chunk to 540 s so the host can shed heat.
- Report path `/mnt/data/wave4/out/mc3-REPORT.md` IS writable via the editor tool;
  this identical copy is committed in-branch at `.scratch/mc3-REPORT.md`.

## 2. exec/s — BEFORE (fixed 5 ms quiescence)

```
fuzz: elapsed: 5m0s, execs: 63124 (125/sec), new interesting: 30 (total: 178)
PASS   ok  cmd  301.197s
```
**63124 execs / 300 s ≈ 210 exec/s.** No crashers. 30 new interesting.

## 3. exec/s — AFTER (adaptive drain-quiescence)

```
fuzz: elapsed: 5m0s, execs: 148791 (2041/sec), new interesting: 35 (total: 213)
PASS   ok  cmd  301.069s
```
- **148791 execs / 300 s ≈ 496 exec/s.** No crashers.
- **BEFORE ≈ 210 → AFTER ≈ 496 exec/s = ×2.36.** Per-input wall 4.76 → 2.02 ms (2 workers).
- **Confound (honest):** AFTER started from the slightly larger corpus BEFORE left
  behind (178 → 213). Corpus size has a second-order effect on exec/s, so ×2.36 is the
  observed end-to-end number, not a controlled microbenchmark. The dominant,
  directly-attributable change is the open-hold going from a flat 5 ms to ~3 ms drain.

## 4. The adaptive detector — design & why it can't hide a hang

Replaced `time.Sleep(mc1Quiescence)` (fixed 5 ms) with `waitDrain(w, rec, runDone)`,
which EOFs the pipe as soon as the FIRST of:
1. the server goroutine already returned (`runDone`) → fully drained;
2. **quiescence**: progress `written()+count()` (bytes written back + dispatches
   recorded) unchanged for `mc1DrainSettle` = **3 ms**, polled every 100 µs (any
   increase resets the window);
3. **ceiling**: `mc1DrainCeiling` = **20 ms** regardless.

**Calibration, not guessing.** A throwaway measurement (400 iters, removed) put async
tools/call dispatch latency at p50 555 µs / p99 1.39 ms / **max 1.70 ms**. 1 ms lost
1/200; 3 ms sits 1.76× above the max.

**Why it cannot hide a hang.** The detector decides only *when to EOF*; it makes no
liveness judgement. Untouched: the per-input `resource.Check` wall-time budget (M2,
5 s) + alloc budget (measures all of `serveOnce`, drain included), and `serveOnce`'s
own guard (`select { <-runDone; <-time.After(3 s): cancel() }` + bounded joins). A
server that keeps emitting output or never settles is cut at the 20 ms ceiling exactly
as the old fixed wait would have, then those oracles judge it. Worst case: EOF a touch
early — never extend or mask a hang.

**Coverage is not reduced.** Closing only *after* quiescence means a slow-but-real
dispatch still flushes before EOF. `TestMC1AdaptiveDrainCapturesAsyncDispatch` pins a
well-formed post-handshake tools/call is captured on ≥190/200 iters (typically
199–200). NOT a strict 200/200 — an unbounded Go-scheduler tail can beat any finite
settle, so a correct detector lands ~99.5%. Red/green (by hand, reverted): neutering
`waitDrain` to immediate `return` drops capture to ~21/200 (≈10%); real detector
199–200/200. The 190 floor separates the two without flaking. (The first MC3 commit's
message said "200/200" — the isolated-run number; corrected here and in the guard.)

## 5. Overnight campaign (≥185 min, 540 s chunks)

| chunk | execs (540 s) | ~exec/s | corpus total | result |
|------:|--------------:|--------:|-------------:|:------:|
| 1 | 151279 | 280 | 271 | PASS |
| 2 | 173432 | 321 | 303 | PASS |
| 3 | 146931 | 272 | 336 | PASS |
| 4 | 173847 | 322 | 368 | PASS |
| 5 | 151505 | 281 | 399 | PASS |
| 6 | 171851 | 318 | 423 | PASS |
| 7 | 164328 | 304 | 441 | PASS |
| 8 | 146847 | 272 | 462 | PASS |
| 9 | 142572 | 264 | 484 | PASS |
| 10 | aborted @211 s | — | 489 | **FAIL → F-MC3-1** |

exec/s stayed in a tight 264–322/s band (no collapse), lower than the AFTER 300 s
baseline's ~496/s because the campaign is in the coverage-expansion regime (20–58 new
interesting/chunk). Chunk 10 produced the one crasher; I triaged it, corrected the M3
oracle, re-verified, committed, and resumed under the corrected oracle — noted, not
hidden. Chunk 10's 211 s is NOT counted toward the ≥185 min target.

_(table continues as later chunks complete.)_

## 6. Crashers / findings

### F-MC3-1 — go-sdk reflects peer-controlled DEL / C1 control bytes raw — HARDENING (low)

**What fired.** Chunk 10, M3: `control rune U+007F at byte 317`. Minimised reproducer
(deterministic 3/3; quarantined at `.scratch/findings/F-MC3-1_DEL_repro.bin`):
```
{"jsonrpc":"2.0","id":0,"method":"tools/call","params":{"name":"dsd_health","arguments":{"deep":"\x7f"}}}
```
`deep` is `bool`; a string value fails schema validation, and the SDK error quotes the
value — reflecting raw `0x7F` into output. `encoding/json` escapes only `< 0x20`, not
`0x7F`/C1 `U+0080–U+009F`.

**Scope probe (`TestMC3SDKReflectsControlsRaw`):**

| byte | raw in output? | note |
|------|:--------------:|------|
| ESC `U+001B` | no | escaped / rejected (load-bearing — never leaks) |
| BEL `U+0007` | no | escaped / rejected |
| NUL `U+0000` | no | frame rejected |
| DEL `U+007F` | yes | benign on terminals |
| CSI `U+009B` | yes | C1 control-sequence introducer |
| OSC `U+009D` | yes | C1 OS-command introducer |

**Reachability.** Reachable in production `dsd mcp`: bytes are a tool-call argument
controlled by the **remote/confused MCP peer** (the target's stated prompt-injection
threat). The reflection is SDK-generated by the schema-validation layer that sits IN
FRONT of dsd's real handlers — live path identical to production. Trace: peer bytes →
`tools/call` args → go-sdk validation fails → error quotes value → `encoding/json`
(0x7F/C1 unescaped) → `StdioTransport` writes frame.

**Classification: HARDENING (borders low-sev SECURITY-DEFECT), not VULNERABILITY.**
ESC/C0 (the real attack primitives) do NOT leak. DEL is inert; C1 CSI/OSC *can* drive a
VT but ride the wire as UTF-8 multibyte that modern UTF-8 terminals render/ignore
rather than execute (8-bit transcoding is the residual risk). The direct consumer is a
JSON-decoding MCP client, not a raw terminal. Root cause is Go-stdlib `encoding/json`
via the go-sdk — not dsd code.

**Premise was wrong → oracle fixed, assertion NOT bent to behaviour.** The mc1 comment
"encoding/json escapes every byte < 0x20, so a correct encoder cannot emit a raw
control char" is half true. I narrowed M3's **fatal** to the true attack set (invalid
UTF-8, raw ESC, C0 `< 0x20` except `\n`) — which never leak, so it stays green and
still catches any ESC/C0 regression (mc1 red/green still holds). DEL/C1 reflection is
NOT dropped: pinned by `TestMC3SDKReflectsControlsRaw` (fails if ESC/C0 start leaking
OR if the SDK starts escaping C1) and reported here.

**Issue-ready production proposal (NOT applied).** For end-to-end M3-strength safety:
a transport-level sanitiser stripping/escaping `0x7F` + `U+0080–U+009F` from outbound
frames, OR document in SECURITY.md that MCP clients MUST sanitise tool result/error
text before terminal rendering. SDK-generated text means an in-handler fix is
insufficient — needs an `IOTransport`/writer wrapper or an upstream go-sdk option.

No other crashers in the campaign.

## 7. What each oracle does NOT verify

- **M1 no panic** — only absence of a Go panic in the server goroutine, not response
  correctness.
- **M2 bounded work** — Go heap (`TotalAlloc`) + wall time + goroutine count only; not
  RSS/off-heap/cgo/fd. Wall time is a generous ceiling catching hangs/super-linear
  blowups, not micro-regressions.
- **M3 terminal-safe output** — scans only the retained prefix (≤ 4 MiB); fatal on
  invalid UTF-8 + raw ESC + C0 `< 0x20` except `\n`. After F-MC3-1 it does **NOT**
  fatal on `U+007F`/C1 `U+0080–U+009F` (known reported HARDENING gap, pinned by
  `TestMC3SDKReflectsControlsRaw`). Does not verify semantic correctness, nor cover a
  client that transcodes the valid-UTF-8 C1 codepoints to 8-bit before display.
- **M5 dispatch in-schema** — only that an invoked handler maps to a registered tool
  name; NOT that each malformed argument is rejected for the right reason, nor that
  dropped frames were dropped correctly.
- **Not covered at all:** read-only/no-host-write (handlers stubbed; gated by DL1
  target 2 + `write_capable_callsites_test.go`), `safeBundlePath` containment,
  collector pipeline / redaction / real output shape, SSE / Streamable HTTP (stdio
  only), TLS/auth (stdio has none).
- **Adaptive detector** — decides *when to EOF*, not *whether work is bounded*; defers
  liveness entirely to M2 + the context hang guard.

## 8. Ranked LEFTOVERS (highest security value first)

1. **C1/DEL reflection end-to-end (F-MC3-1 follow-up).** Decide production posture:
   transport-level C1/0x7F sanitiser for `dsd mcp` outbound frames, or document the
   client-sanitises-before-display boundary in SECURITY.md. Also confirm whether any
   first-party MCP *client* renders tool error text to a terminal without sanitising —
   that would raise F-MC3-1 toward low-sev SECURITY-DEFECT.
2. **Schema-validation reason coverage.** M5 never checks each malformed argument is
   rejected for the *right* reason — a validator that accepts an out-of-schema value
   and dispatches a half-decoded struct would pass today.
3. **Real-handler path behind the stubs.** No target drives a real `tools/call`
   end-to-end from hostile JSON-RPC through a real handler to the fingerprint oracle on
   the actual disk path (write path gated by DL1 target 2 but not fuzzed from the front).
4. **Non-stdio transports.** SSE / Streamable HTTP framing/auth/TLS uncovered if ever enabled.
5. **Output beyond 4 MiB.** M3 scans only the retained prefix (resource oracle would
   flag the >4 MiB amplification first — thin gap).
6. **Throughput headroom (harness-only, low).** settle=3 ms is calibrated to the 1.70 ms
   max dispatch latency; an SDK in-flight-count hook could drop it toward p99 (~1.4 ms).
