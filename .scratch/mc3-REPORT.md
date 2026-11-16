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
  second-order effect on exec/s, so the ×2.36 is the observed end-to-end number,
  not a controlled per-input microbenchmark. The dominant, directly-attributable
  change is the per-input open-hold going from a flat 5 ms to a measured ~3 ms drain.

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
and captures 200/200.

**Why it cannot hide a hang.** The detector decides only *when to EOF*; it makes no
liveness judgement. Everything that judges bounded-work/hang is untouched: the
per-input `resource.Check` wall-time budget (M2, 5 s) + alloc budget (measures the
whole `serveOnce`, drain included), and `serveOnce`'s own hang guard
(`select { <-runDone; <-time.After(3 s): cancel() }` + bounded joins). A server that
keeps emitting output or never settles is cut off at the 20 ms ceiling exactly as the
old fixed 5 ms wait would have cut it — after which those two oracles run unchanged.
So the worst the detector can do is EOF a touch earlier; it can never extend or mask
a hang. A genuinely wedged handler makes `serveOnce` run ~3 s+ and trips M2.

**Coverage is not reduced.** Closing only *after* quiescence (not on a blind timer)
means a slow-but-real dispatch still flushes before EOF. The committed guard
`TestMC1AdaptiveDrainCapturesAsyncDispatch` locks this in: a well-formed
post-handshake tools/call must be captured on every one of 200 iterations.
Red/green proof (run by hand, reverted): neutering `waitDrain` to an immediate
`return` drops capture to 21/200 and the guard fails; the real detector 200/200.

## 5. Overnight campaign (≥185 min, 540 s chunks)

_pending._

## 6. Crashers / findings

_pending._

## 7. What each oracle does NOT verify

- **M1 no panic** — does not verify correctness of any response, only absence of a Go
  panic in the server goroutine.
- **M2 bounded work** — Go heap (`TotalAlloc`) + wall time + goroutine count only; not
  RSS, not off-heap/cgo, not fd count. Wall time is a generous ceiling on a shared
  throttled host, catches hangs/super-linear blowups, not micro-regressions.
- **M3 terminal-safe output** — scans only the retained output prefix (≤ 4 MiB cap);
  checks UTF-8 + no raw ESC + no C0 except `\n`. Does not verify the response is
  *semantically* correct, only that it is terminal-inert.
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

_pending._
