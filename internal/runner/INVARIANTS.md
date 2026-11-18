# internal/runner — invariants

The runner fans a slice of `Collector`s out across goroutines, bounds each with
its own timeout, recovers panics, and keeps the whole run bounded even when a
collector ignores its context. These are the lifecycle and resource-hygiene
invariants the package must preserve; RN1 fuzz targets
(`rn1_lifecycle_fuzz_test.go`, `rn1_exechygiene_fuzz_linux_test.go`) are the
standing guards, each with a red/green proof.

## Runner lifecycle (`RunAll` / `runOne`)

1. **Every collector yields exactly one `Result`.** `len(results) == len(collectors)`
   on both the live (concurrent) and replay (serial `GapCount`) paths.

2. **A timed-out collector is never a silent OK.** A collector that misses its
   deadline (a ctx-ignoring hang, or a ctx-respecting but slow collector) returns
   `Result.Err` set to `context.DeadlineExceeded`/`Canceled` with `Result.Data ==
   nil`. A panicking collector returns a non-nil `Result.Err` ("collector X
   panicked"). This is the runner half of the product's "unverified, never a
   silent OK when a signal could not be read" guarantee — downstream,
   `analysis` turns that `Result.Err` into an INFO *unverified* insight.

3. **Wall time is bounded by the single longest timeout, not by collector count.**
   The result channel closes within `max(timeout_i) + collectGrace + scheduling`
   — concurrency, never serialization. A ctx-ignoring collector cannot extend the
   run beyond its own `Timeout() + collectGrace`.

4. **An abandoned collector goroutine is bounded and drainable, never a permanent
   leak.** When a ctx-ignoring collector misses its deadline, `runOne` synthesizes
   a timeout `Result` and leaves the `Collect` goroutine parked. Because `done` is
   **buffered (cap 1)**, that goroutine's eventual late send never blocks, so the
   goroutine exits the moment its blocking call returns. Across a run, the number
   of abandoned goroutines equals exactly the number of collectors still inside an
   uncancellable call — no other goroutine leaks. *If `done` is ever unbuffered,
   invariant 4 breaks: the late send blocks forever and the goroutine leaks
   permanently (RN1 O1 red proof).* 

5. **Determinism.** For a fixed set of collectors with outcome-deterministic
   behaviour, the aggregated report (results keyed by name) is identical
   regardless of the nondeterministic completion order.

6. **Output is passed through untouched.** `RunAll` neither drops nor duplicates a
   collector's `Data`; aggregate output equals the sum of what the collectors
   produced.

## Collector-execution path (`source.Live.Run` → `platform.RunHardened`)

7. **No fd leak.** Every exec closes its stdout/stderr pipes on all paths
   (success, non-zero exit, timeout-kill, signal-ignoring kill): `cmd.Run` always
   `Wait`s.

8. **No leftover process.** `cmd.Run` reaps the child on every path (BUG-021); no
   zombie and no orphan parented by dsd survives the call. A signal-ignoring child
   is still reaped because `exec.CommandContext` cancels with `SIGKILL`, and
   `cmd.WaitDelay = platform.ExecWaitDelay` force-kills a child that outlives its
   context.

9. **Captured output is bounded.** stdout/stderr are read through
   `source.NewCapWriter(source.MaxCapturedOutput)` (64 MiB/stream), so a flooding
   child cannot exhaust memory.

10. **No temp file of dsd.** The exec path leaves no file behind (a pinned TMPDIR
    tree is byte-for-byte unchanged across a run).
