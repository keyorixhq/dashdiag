# internal/readonly — invariants

Test-only package (every file is `_test.go`, build tag `//go:build linux`). It is
RO1's end-to-end harness for DashDiag's central product claim: **a collector run
is read-only and makes no non-loopback network call**. It ships no production code
and must never be imported by production code.

## Invariants this package asserts (per fuzzed input)

1. **Read-only filesystem.** With `HOME`, `TMPDIR` and `cwd` pinned to fresh empty
   temp dirs, the combined tree's DL1 `resource.Fingerprint` is byte-identical
   before and after running every collector. A persistent watched-host sentinel
   tree (outside every per-input dir) is likewise unchanged.
2. **Read-only exec.** Every command dsd attempts (observed via
   `platform.ExecHook`, which also DENIES it so nothing runs) matches the
   read-only allowlist `execAllowlistContract` — a port of
   `cmd_test.execAllowlistContract` — on both binary membership and read-only argv
   prefix, with no `denyAnywhere` token. A mutating invocation matches no prefix.
3. **No non-loopback network.** `http.DefaultTransport` and `net.DefaultResolver`
   are replaced in `TestMain` so any dial to a non-loopback address is recorded
   and denied; a recorded dial fails the input.
4. **PATH shim net.** `$PATH` is replaced by recording shims. Any shim firing
   means an exec bypassed `platform.ExecHook` (stdlib/cgo/third-party); a shim for
   a non-allowlisted or mutating command fails the input.

## Invariants the package itself must preserve

- `platform.ExecHook` is set only inside this test binary's `TestMain` and reset
  to `nil` after. It must stay `nil` in production.
- `execAllowlistContract` is a *deliberate copy* of the hand-reviewed upstream
  contract; any divergence is a correction of a verified read-only call site
  missing upstream, documented at the entry and in the RO1 report, never a
  silent broadening to make a failing input pass.
- The run+assert critical section is serialised by `runMu` because the exec
  recorder, net guard and shim trace are process globals; do not remove this lock
  while those remain global, or `-parallel >1` makes the oracles unsound.

## What these oracles do NOT verify

See the "What each oracle does NOT verify" section of the RO1 report
(`out/ro1-REPORT.md`): among others — execs/dials made by Go stdlib or cgo that
bypass both `platform.ExecHook` and `http.DefaultTransport`/`net.DefaultResolver`
(e.g. raw `net.Dial`, ICMP via raw sockets), writes to absolute host paths outside
the watched set, root-only code paths, and a write-then-restore within one run.
