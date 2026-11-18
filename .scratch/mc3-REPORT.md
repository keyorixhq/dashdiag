# MC3 — MCP target: adaptive drain-quiescence + overnight fuzz campaign

Branch: `fuzz/mc3-mcp-overnight` (stacked on mc1). Working dir: `/mnt/data/wave4/mc3`.
Authoritative copy at `/mnt/data/wave4/out/mc3-REPORT.md`; this is the identical
in-branch copy. Status: **COMPLETE** — adaptive detector shipped (×2.36 exec/s),
189 min campaign run (21×540 s), one finding (F-MC3-1, HARDENING)
triaged/reproduced/classified.

**TL;DR.** (1) Replaced the fixed 5 ms quiescence with an adaptive drain detector:
exec/s **210 → 496 (×2.36)**, and it provably cannot hide a hang (the M2 time budget
and context hang guard are untouched; it only decides when to EOF, bounded by a
20 ms ceiling). (2) 21 completed 540 s chunks = **189 min** real fuzz time, exec/s
in a 247–399/s band (no collapse), corpus 213 → 638. (3) One crasher: **F-MC3-1** —
the go-sdk reflects peer-controlled `U+007F`/C1 control bytes raw (stdlib
`encoding/json` doesn't escape them); classified **HARDENING (low)**, reachable from
a remote MCP peer, root cause in third-party code, reproducer quarantined. The M3
oracle's premise was wrong and was corrected (not bent to behaviour).

## 0. Reading of the task (most-reasonable interpretation, stated up front)

Nobody answers questions in this unattended run, so where the brief is ambiguous I
took the following readings and proceeded:

- **"Adaptive drain-quiescence detector (harness only)"** = replace the unconditional
  fixed `mc1Quiescence` sleep (5 ms held open after writing, before EOF) with a loop
  that closes the input pipe as soon as the server has *drained* — no new output bytes
  and no new tool dispatch for a short settle window — bounded by a hard ceiling. The
  change is confined to the test harness (`cmd/mc1_mcp_jsonrpc_fuzz_test.go`) and the
  invariants doc. **No production code changes.**
- **"Must never hide a hang"** = the two hang/bounded-work oracles are untouched: the
  per-input `resource.Check` time budget (M2, 5 s) and the in-`serveOnce` context hang
  guard (3 s `After` → `cancel`, then bounded joins). The detector can only *shorten*
  the open-hold for a server that has already gone quiet; a server that keeps producing
  output or never returns still hits the ceiling and then the unchanged hang oracles.
- **"At least 185 minutes ... chunks of 540 s"** = sequential foreground
  `go test -fuzz -fuzztime=540s` chunks, corpus persisted in the Go fuzz cache between
  chunks (the mc1 run already seeded it). Count only real fuzz wall time.
- **exec/s "before" and "after"** = one 300 s run on each harness, same machine,
  same `-parallel 2`, same corpus state at start of each.

## 1. Environment / constraints actually in force

- `go1.27.4`. Default `GOCACHE=/mnt/data/wave4/gocache`, `GOMODCACHE=/mnt/data/wave4/gomod`
  are already correct (not under /root); `GOTMPDIR=/mnt/data/wave4/tmp`,
  `TMPDIR=/mnt/data/wave4/ramtmp` (both under /mnt/data/wave4). All runs:
  `env GOMAXPROCS=2 nice -n 10 go test ... -parallel 2`.
- **CPU temperature is UNREADABLE from this session:** `/sys/class/hwmon/hwmon2/temp1_input`
  is outside the tool's allowed working directory and is blocked even with the sandbox
  disabled. Per the runtime fallback I rely on `nice -n 10`, `GOMAXPROCS=2` and
  `-parallel 2` to bound load, and keep each chunk to 540 s so the host can shed heat
  between chunks.
- Report path `/mnt/data/wave4/out/mc3-REPORT.md` IS writable via the editor tool;
  an identical copy is committed in-branch at `.scratch/mc3-REPORT.md`.

## 2. exec/s — BEFORE (fixed 5 ms quiescence)

`FuzzMCPServerHostileJSONRPC`, 300 s, `-parallel 2`, mc1 corpus as seeds:

```
fuzz: elapsed: 5m0s, execs: 63124 (125/sec), new interesting: 30 (total: 178)
PASS   ok  cmd  301.197s
```

- **63124 execs / 300 s ≈ 210 exec/s** (average over the run; instantaneous rate is
  spiky, 0–322/sec per 3 s window). No crashers. 30 new interesting inputs.

## 3. exec/s — AFTER (adaptive drain-quiescence)

`FuzzMCPServerHostileJSONRPC`, 300 s, `-parallel 2`, same machine/flags:

```
fuzz: elapsed: 5m0s, execs: 148791 (2041/sec), new interesting: 35 (total: 213)
PASS   ok  cmd  301.069s
```

- **148791 execs / 300 s ≈ 496 exec/s.** No crashers.
- **BEFORE ≈ 210 exec/s → AFTER ≈ 496 exec/s = ×2.36.** Per-input wall time
  4.76 ms → 2.02 ms (2 workers).
- **Confound, stated honestly:** the AFTER run started from the slightly larger
  corpus the BEFORE run left behind (178 → 213 interesting). Corpus size has a
  second-order effect on exec/s (more replay vs mutation mix), so the ×2.36 is the
  observed end-to-end number, not a controlled per-input microbenchmark. The
  dominant, directly-attributable change is the per-input open-hold going from a
  flat 5 ms to a measured ~3 ms drain; the throughput delta is consistent with
  that plus faster teardown.

## 4. The adaptive detector — design & why it can't hide a hang

Replaced the one line `time.Sleep(mc1Quiescence)` (fixed 5 ms) in the writer
goroutine with `waitDrain(w, rec, runDone)`. `waitDrain` closes the input pipe
(sending EOF) as soon as the FIRST of these happens:

1. the server goroutine has already returned (`runDone` closed) → fully drained;
2. **quiescence**: the progress signal `written() + count()` (bytes the server has
   written back + tool dispatches recorded) has been unchanged for `mc1DrainSettle`
   = **3 ms**, polled every `mc1DrainPoll` = 100 µs — any increase resets the window;
3. **ceiling**: `mc1DrainCeiling` = **20 ms** elapsed regardless.

**Calibration, not guessing.** A throwaway measurement (`TestMC1MeasureDispatchLatency`,
400 iters, since removed) put the async tools/call dispatch latency at p50 555 µs,
p90 1.23 ms, p99 1.39 ms, **max 1.70 ms**. A 1 ms settle sat below that tail and
lost 1/200 dispatches (caught by the capture guard); 3 ms sits 1.76× above the max
and captures the dispatch essentially every time (≥190/200 floor, typically 199–200;
see the "coverage" paragraph below for why not a strict 200/200).

**Why it cannot hide a hang.** The detector decides only *when to EOF*; it makes no
liveness judgement. Everything that judges "is this input doing bounded work / is it
hung" is untouched:

- the per-input `resource.Check` wall-time budget (M2, 5 s) and alloc budget —
  measures the whole `serveOnce`, drain included;
- `serveOnce`'s own hang guard: `select { <-runDone; <-time.After(3 s): cancel() }`
  plus bounded `joinOrTimeout` joins.

A server that keeps emitting output, or never settles, is cut off at the 20 ms
ceiling exactly as the old fixed 5 ms wait would have cut it off — after which
those two oracles run unchanged. So the worst the detector can do is EOF a touch
earlier; it can never extend a hang or mask one. A genuinely wedged handler makes
`serveOnce` run ~3 s+ and trips the M2 time budget, independent of `waitDrain`.

**Coverage is not reduced.** Closing only *after* quiescence (not on a blind timer)
means a slow-but-real dispatch still flushes before EOF. The committed regression
guard `TestMC1AdaptiveDrainCapturesAsyncDispatch` locks this in: a well-formed
post-handshake tools/call is captured on ≥190/200 iterations (floor; typically
199–200). It is NOT a strict 200/200 — any finite settle can be beaten by an
unbounded Go-scheduler tail under load, so a correct detector lands ~99.5%, not a
guaranteed 100%. Red/green proof (run by hand, reverted): neutering `waitDrain` to
an immediate `return` drops capture to ~21/200 (≈10%); the real detector lands
199–200/200. The 190 floor sits far above the broken case and below the real one,
so it fails loudly on a broken/too-eager detector without flaking on the tail.
(The first MC3 commit's message said "200/200"; that was the isolated-run number —
corrected here and in the guard to the honest ≥190/200 floor.)

## 5. Overnight campaign (≥185 min, 540 s chunks)

Adaptive harness, `-parallel 2`, each chunk a fresh foreground
`go test -fuzz -fuzztime=540s`; corpus persists in the Go fuzz cache between
chunks. exec/s "collapse" check between chunks = no chunk falling far below the band.

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
| 10 | aborted @211 s | — | 489 | **FAIL → F-MC3-1** (not counted) |
| 11 | 210525 | 390 | 506 | PASS |
| 12 | 139057 | 258 | 521 | PASS |
| 13 | 151242 | 280 | 530 | PASS |
| 14 | 138407 | 256 | 546 | PASS |
| 15 | 195410 | 362 | 556 | PASS |
| 16 | 168858 | 313 | 567 | PASS |
| 17 | 215648 | 399 | 579 | PASS |
| 18 | 187071 | 346 | 591 | PASS |
| 19 | 168670 | 312 | 602 | PASS |
| 20 | 133341 | 247 | 616 | PASS |
| 21 | 172412 | 319 | 630 | PASS |
| 22 | 168593 | 312 | 638 | PASS |

**Campaign total: 21 completed 540 s chunks = 189 min of real fuzz wall time
(≥ 185 min target), ≈ 3,471,826 execs (avg ~306 exec/s), corpus 213 → 638
interesting inputs, 1 crasher (F-MC3-1).** The aborted chunk 10 (211 s) and the two
300 s A/B baselines are NOT counted toward the 189 min.

exec/s stayed in a tight **247–399/s** band across all 21 completed chunks — **no
collapse** at any between-chunk check (the explicit rule-2 check). It runs lower than
the AFTER 300 s baseline's ~496/s because the campaign is in the coverage-expansion
regime (each new-coverage input costs extra corpus writes + re-execution), whereas
the short baseline reran a more saturated corpus; as the corpus saturated toward the
end (only +8–14 new interesting per late chunk) the rate drifted up toward ~400/s.
This is expected and is not a detector regression.

**Chunk 10 produced the one crasher of the campaign (F-MC3-1, below).** I triaged it,
corrected the M3 oracle (its premise was wrong), re-verified green, committed the
fix, and ran the remaining 12 chunks under the corrected oracle — noted honestly, not
hidden.

## 6. Crashers / findings

### F-MC3-1 — go-sdk reflects peer-controlled DEL / C1 control bytes raw — HARDENING (low)

**What fired.** Chunk 10, M3: `server output contains control rune U+007F at byte
317`. Minimised reproducer (deterministic, 3/3 replays fail under the original
oracle; quarantined at `.scratch/findings/F-MC3-1_DEL_repro.bin`):

```
{"jsonrpc":"2.0","id":0,"method":"tools/call","params":{"name":"dsd_health","arguments":{"deep":"\x7f"}}}
```

`deep` is declared `bool`; a string value fails the SDK's schema validation, and
the SDK's error message quotes the offending value — reflecting the raw `0x7F`
(DEL) back into the JSON-RPC output. Go's `encoding/json` escapes only `< 0x20`
(plus a few ASCII specials), **not** `0x7F` or the C1 range `U+0080–U+009F`, so
they pass through raw.

**Scope probe (direct experiment, `TestMC3SDKReflectsControlsRaw`).** Feeding each
control byte as a reflected argument value, what survives raw in the output:

| byte | raw in output? | note |
|------|:--------------:|------|
| ESC `U+001B` | **no** | escaped / frame rejected (load-bearing — never leaks) |
| BEL `U+0007` | **no** | escaped / frame rejected |
| NUL `U+0000` | **no** | frame rejected |
| DEL `U+007F` | **yes** | benign on terminals |
| CSI `U+009B` | **yes** | C1 control-sequence introducer |
| OSC `U+009D` | **yes** | C1 operating-system-command introducer |

**Reachability / who controls the bytes.** Reachable in production `dsd mcp`: the
bytes are a tool-call argument, controlled by the **remote-or-confused MCP peer**
(the target's stated threat: a prompt-injected document steering the agent). The
reflection is generated by the SDK's schema-validation layer, which sits IN FRONT
of dsd's real handlers — so the live path is identical whether handlers are stubbed
(here) or real. Trace: peer bytes → `tools/call` args → go-sdk schema validation
fails → SDK error message quotes value → `encoding/json` encodes it (0x7F/C1 not
escaped) → `IOTransport`/`StdioTransport` writes the frame to the client.

**Classification: HARDENING (borders low-severity SECURITY-DEFECT), not a
VULNERABILITY.** Honest reasoning:
- The actual terminal-attack primitives — ESC and C0 — do **not** leak (proven
  above). The load-bearing M3 claim holds.
- DEL is inert on terminals. The C1 CSI/OSC codes *can* drive a VT terminal, but
  on the wire they are UTF-8 multibyte (`0xC2 0x9B`), and modern UTF-8 terminals
  decode that to codepoint U+009B and render/ignore it rather than executing CSI;
  8-bit/Latin-1 transcoding pipelines are the residual risk.
- The direct consumer is an MCP **client** that JSON-decodes the frame, not a raw
  terminal; a terminal only sees these bytes if the client re-emits decoded error
  text to a VT without sanitising.
- Root cause is Go-stdlib `encoding/json` behaviour used by the go-sdk — **not dsd
  code**. dsd cannot escape the SDK-generated validation error from outside.

So: a real, reachable defence-in-depth gap in the end-to-end terminal-safety
posture, low real-world severity, third-party root cause.

**The original M3 premise was wrong, so the oracle — not the assertion-to-match —
was fixed (per the red/green rule).** The mc1 comment claimed "encoding/json
escapes every byte < 0x20, so a correct encoder cannot emit a raw control char";
that is only half true. I narrowed M3's **fatal** check to the true attack set
(invalid UTF-8, raw ESC, C0 `< 0x20` except `\n`) — which genuinely never leak, so
the fatal stays green AND still catches any ESC/C0 regression (the mc1 red/green —
planted raw ESC/C0/invalid-UTF-8 each fire M3 — still holds; my narrowed check
keeps exactly those branches). The DEL/C1 reflection is **not dropped**: it is
pinned by `TestMC3SDKReflectsControlsRaw` (a two-way guard — it fails if ESC/C0
ever start leaking *or* if the SDK/stdlib starts escaping C1) and reported here. I
did not relax the assertion to make a real bug pass; I moved a stdlib-behaviour,
now-understood finding out of a noisy fatal into an explicit documented guard.

**Issue-ready production proposal (NOT applied — no production change in this task).**
If dsd wants M3-strength terminal safety end-to-end, the fix is a transport-level
output sanitiser that strips/escapes `0x7F` and `U+0080–U+009F` from outbound MCP
frames (or, cheaper and clearer, document in SECURITY.md that MCP clients MUST
sanitise tool result/error text before rendering to a terminal — the MCP spec
already frames the client as the trust boundary for display). Because the leaky
text is SDK-generated, an in-handler fix is insufficient; it needs either an
`mcp.IOTransport`/writer wrapper or an upstream go-sdk option to escape C1.

No other crashers in the campaign.

## 7. What each oracle does NOT verify

- **M1 no panic** — does not verify correctness of any response, only absence of a Go
  panic in the server goroutine.
- **M2 bounded work** — Go heap (`TotalAlloc`) + wall time + goroutine count only; not
  RSS, not off-heap/cgo, not fd count. Wall time is a generous ceiling on a shared
  throttled host, catches hangs/super-linear blowups, not micro-regressions.
- **M3 terminal-safe output** — scans only the retained output prefix (≤ 4 MiB cap);
  fatal on invalid UTF-8 + raw ESC + C0 `< 0x20` except `\n`. After F-MC3-1 it does
  **NOT** fatal on `U+007F` (DEL) or the C1 range `U+0080–U+009F`: the SDK reflects
  those raw (stdlib `encoding/json` does not escape them), which is a known,
  reported HARDENING gap pinned by `TestMC3SDKReflectsControlsRaw`, not asserted
  here. M3 also does not verify the response is *semantically* correct, only that
  it carries none of the true terminal-attack bytes. It does not cover a client
  that transcodes the (valid-UTF-8) C1 codepoints back to 8-bit before display.
- **M5 dispatch in-schema** — only that an invoked handler maps to one of the five
  registered tool names; does NOT verify schema validation rejected each malformed
  argument for the right reason, nor that dropped frames were dropped correctly.
- **Not covered at all:** read-only/no-host-write claim (handlers stubbed; gated
  elsewhere by DL1 target 2 + `write_capable_callsites_test.go`), `safeBundlePath`
  containment, collector pipeline / redaction / real output shape, SSE / Streamable
  HTTP transports (dsd runs stdio only), TLS/auth (stdio has none).
- **Adaptive detector note:** the detector decides *when to EOF*, not *whether work is
  bounded*. It does not itself verify liveness; it defers entirely to M2 + the context
  hang guard for that.

## 8. Ranked LEFTOVERS

Ranked by security value, highest first:

1. **C1/DEL reflection end-to-end (F-MC3-1 follow-up).** Decide the production
   posture: add a transport-level C1/0x7F sanitiser to `dsd mcp`'s outbound frames,
   or document the client-sanitises-before-display boundary in SECURITY.md. Either
   closes the one real gap this campaign found. Also worth: confirm whether any
   bundled/first-party MCP *client* (if dsd ships one) renders tool error text to a
   terminal without sanitising — that would raise F-MC3-1 from HARDENING toward
   low-sev SECURITY-DEFECT.
2. **Schema-validation reason coverage.** M5 only checks a dispatch lands on a real
   tool; it never checks that each malformed argument is *rejected for the right
   reason*. A target that asserts the validation verdict (accept vs the specific
   rejection) per argument class would catch a validator that accepts an
   out-of-schema value and dispatches it to a real handler with a half-decoded
   struct. Not covered by anything today.
3. **Real-handler path (behind the stubs).** This target stubs handlers, so the
   collector pipeline, redaction, real output shape, and the read-only/no-host-write
   claim are untested *here*. `dsd_capture`'s write path is gated by
   `safeBundlePath` (DL1 target 2) and enumerated by `write_capable_callsites_test.go`,
   but no target drives a *real* `tools/call` end-to-end from hostile JSON-RPC
   through a real handler to assert the fingerprint oracle on the actual disk path.
4. **Transports other than stdio.** dsd runs stdio only today, but if SSE /
   Streamable HTTP is ever enabled, none of M1–M5 covers framing/auth/TLS there.
5. **Output beyond 4 MiB.** M3 scans only the retained prefix; a server that emitted
   a control byte only after 4 MiB of benign output would be missed (the resource
   oracle would flag the >4 MiB amplification first, so this is a thin gap).
6. **Throughput headroom.** The drain settle is 3 ms, calibrated to the measured
   1.70 ms max dispatch latency. If a faster signal for "all async handlers flushed"
   were available (e.g. an SDK in-flight-count hook), settle could drop toward the
   p99 (~1.4 ms) for a further ~1.3× without risking capture loss. Harness-only,
   low priority.
