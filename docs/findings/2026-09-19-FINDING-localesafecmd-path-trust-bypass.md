# FINDING: `localeSafeCmd`'s two call sites (`ping`, `route`) skip PATH-trust resolution

**Date:** 2026-09-19
**Severity:** low
**Status:** reported, not fixed (per fuzzing-campaign policy: report, don't fix)
**Component:** `internal/collectors/collector.go`'s `localeSafeCmd`, called
from `internal/collectors/network_quick.go:421` (`ping`) and `:634` (`route
-n get default`, macOS only)

## Summary

Every other exec call site in the repo resolves the binary name through
`platform.ResolveTrustedTool` before exec'ing — a fixed system-directory
allowlist that deliberately ignores the inherited `$PATH`, closing a
PATH-hijack vector for a process that routinely runs as root (see
`internal/platform/trustedexec.go`'s doc comment). `localeSafeCmd`
(`internal/collectors/collector.go`, the helper `sysPing` and
`detectGatewayDarwin` use for `.Output()`-style raw `*exec.Cmd` construction)
is the one exception: it execs the bare `name` argument directly —

```go
func localeSafeCmd(ctx context.Context, name string, args ...string) (*exec.Cmd, error) {
    ...
    cmd := exec.CommandContext(ctx, name, args...)
    ...
}
```

— relying on Go's own `os/exec` PATH search, exactly the behavior
`ResolveTrustedTool` exists to avoid everywhere else.

## Evidence

Found via direct code read while wiring `platform.ExecHook` into every exec
call site for `FuzzCommandAllowlist` (STEP 2 of the read-only-invariant
fuzzing campaign): `localeSafeExec` (the *other*, more heavily used function
in the same file, one line below) does call `platform.ResolveTrustedTool`;
`localeSafeCmd` does not. Confirmed by inspecting both call sites
(`network_quick.go:421,634` — `ping` and `route -n get default`) and finding
no `ResolveTrustedTool` anywhere on either path.

`cmd/execallowlist_contract_test.go`'s `execAllowlistKnownException` map
documents this explicitly (`KV-PING-ROUTE-UNRESOLVED`) so `FuzzCommandAllowlist`'s
allowlist oracle states the gap rather than silently relying on the
coincidence that "ping" and "route" also happen to be valid resolved
basenames.

## Impact

Low: `ping` and `route -n get default` are both narrowly-scoped, low-value
targets for a PATH hijack (unlike e.g. `systemctl` or `rpm`, a substituted
`ping`/`route` binary mainly lets an attacker feed dsd fabricated
RTT/gateway data — it doesn't unlock a more consequential capability). Still
a real, avoidable inconsistency with the rest of the codebase's exec
hardening.

## Suggested fix shape (not applied)

Route `localeSafeCmd` through `platform.ResolveTrustedTool(name)` exactly
like `localeSafeExec` one line below it does. This overlaps with — but is
narrower and more urgent than — the separate "consolidate the ~10 duplicated
exec call sites behind one hardened helper" enhancement drafted alongside
this campaign's other GitHub issues.

## Tracking

`KV-PING-ROUTE-UNRESOLVED` in `cmd/knownviolations_test.go` /
`cmd/execallowlist_contract_test.go`. GitHub issue: see
`docs/findings/2026-09-19-github-issue-drafts.md`.
