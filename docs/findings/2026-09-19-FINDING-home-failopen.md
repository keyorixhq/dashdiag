# FINDING: three `$HOME`-dependent path functions fail open to a CWD-relative path

**Date:** 2026-09-19
**Severity:** low
**Status:** reported, not fixed (per fuzzing-campaign policy: report, don't fix)
**Component:** `internal/baseline/baseline.go:67` (`baselineDir`),
`internal/baseline/golden.go:11` (`goldenDir`),
`internal/baseline/security_baseline.go:63` (`SecurityBaselinePath`)

## Summary

All three functions resolve a write path under `$HOME/.dsd/...` the same way:

```go
home, _ := os.UserHomeDir()
return filepath.Join(home, ".dsd", "baselines") // (or "golden", or "security-baseline.json")
```

The error from `os.UserHomeDir()` is discarded. On Unix, `os.UserHomeDir()`
simply returns `$HOME`; if `$HOME` is unset or empty, it returns `("", error)`.
Since the error is ignored, `home` becomes `""`, and `filepath.Join("", ".dsd", ...)`
silently produces a **CWD-relative** path (`.dsd/baselines`, `.dsd/golden`,
`.dsd/security-baseline.json`) instead of refusing to resolve.

This is the exact class of bug the *other* three `$HOME`-dependent call sites
in the repo were deliberately hardened against: `internal/tips/state.go`,
`internal/selfupdate/nudge.go`, and `internal/store/jsonl.go` all guard against
an empty/unresolved home directory and refuse to write rather than falling
back to CWD. These three do not — inconsistent hardening of the same idiom
across the same package family.

## Evidence

Deterministic regression test:
`internal/baseline/homefailopen_test.go::TestHomeFailOpen_KnownViolations`.
With `$HOME` unset:

```
=== RUN   TestHomeFailOpen_KnownViolations
=== RUN   TestHomeFailOpen_KnownViolations/baselineDir
=== RUN   TestHomeFailOpen_KnownViolations/goldenDir
=== RUN   TestHomeFailOpen_KnownViolations/SecurityBaselinePath
--- PASS: TestHomeFailOpen_KnownViolations (0.00s)
```

All three return the CWD-relative shape (`.dsd/baselines`, `.dsd/golden`,
`.dsd/security-baseline.json`), confirming the fail-open path is live.

## Impact

Affects `dsd security --save-baseline`, `dsd baseline save`/`diff`, and the
`--since-deploy`-adjacent baseline-snapshot path — all opt-in, operator-invoked
flows, not the default `dsd health` path. If an operator runs one of these
with `$HOME` unresolvable (a stripped-down container/init environment, a
misconfigured service unit), the write silently lands wherever the process's
current working directory happens to be, rather than erroring — a
CWD-hijack-adjacent surprise (an unexpected file appears next to whatever the
operator was doing) rather than a direct security compromise, since no
attacker-controlled value flows into the path itself.

## Suggested fix shape (not applied)

Mirror `tips/state.go`'s pattern: check `os.UserHomeDir()`'s error (or the
empty-string result) and return an explicit "cannot resolve $HOME" error
instead of falling through to `filepath.Join("", ...)`.

## Tracking

`KV-HOME-FAILOPEN-BASELINE` / `KV-HOME-FAILOPEN-GOLDEN` /
`KV-HOME-FAILOPEN-SECBASELINE` in `cmd/knownviolations_test.go`. GitHub issue:
see `docs/findings/2026-09-19-github-issue-drafts.md`.
