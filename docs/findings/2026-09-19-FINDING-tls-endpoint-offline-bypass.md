# FINDING: `dsd tls --endpoint` dials out even with `DSD_OFFLINE=1`

**Date:** 2026-09-19
**Severity:** medium
**Status:** reported, not fixed (per fuzzing-campaign policy: report, don't fix)
**Component:** `internal/collectors/tls_remote.go` (`CheckRemoteEndpoint` /
`checkRemoteEndpointLive`), invoked from `cmd/tls.go:390` (`dsd tls --endpoint host:port`)

## Summary

Every other remote-dialing or network-capable code path in dsd is gated by
the single, documented network policy in `internal/platform/network_policy.go`
(`platform.NetworkAllowed()` — off by default, opt-in via `--network`/
`DSD_ALLOW_NETWORK`, and always hard-overridden off by `DSD_OFFLINE`).
`CheckRemoteEndpoint` is the one exception: it dials `endpoint` unconditionally,
with no `NetworkAllowed()`/`DSD_OFFLINE` check anywhere on its path.

## Evidence

Deterministic regression test:
`internal/collectors/tls_remote_offline_test.go::TestTLSEndpointBypassesOfflineGate`.
It sets `DSD_OFFLINE=1`, stands up a self-signed TLS listener on
`127.0.0.1:0` (loopback only — no real external host is ever contacted), and
calls `CheckRemoteEndpoint` against it. The dial succeeds despite the offline
flag:

```
=== RUN   TestTLSEndpointBypassesOfflineGate
--- PASS: TestTLSEndpointBypassesOfflineGate (0.01s)
```

(A "PASS" here demonstrates the bug: the test's assertion is that the dial
*succeeds* under `DSD_OFFLINE=1`, which is the violation. If the underlying
bug is fixed — the dial gets refused/blocked — this test will start failing;
at that point delete it along with this finding.)

## Impact

`dsd tls --endpoint <host:port>` is an explicit, operator-invoked command —
not part of the default `dsd health` surface — so this is not a "network
call fires unexpectedly" bug in the sense of DashDiag's "works offline by
default" promise. The impact is narrower: an operator who has explicitly set
`DSD_OFFLINE=1` (e.g., in an air-gapped or compliance-sensitive environment,
expecting it to be a hard kill-switch for all outbound dsd traffic) gets a
live network connection anyway if they separately run `dsd tls --endpoint`.
That breaks the "one policy, one gate" invariant `network_policy.go`'s own
doc comment states.

## Suggested fix shape (not applied)

Add a `platform.NetworkAllowed()` check at the top of
`checkRemoteEndpointLive` (or `CheckRemoteEndpoint`, before the `cachedJSON`
call), matching every other network call site in the repo, returning a clear
"network disabled (DSD_OFFLINE set)" error instead of dialing.

## Why not fuzzed directly

`FuzzCommandAllowlist` (`cmd/execallowlist_fuzz_test.go`) deliberately
excludes the `tls` subcommand from its fuzzed corpus — letting a fuzzer hand
arbitrary `--endpoint` values to a live-dialing code path is a real-network
safety hazard in the harness itself (RULES: no real network in oracles),
independent of this bug. This finding was produced by the STEP 1 code-review
investigation and confirmed here with a narrow, loopback-only deterministic
test instead.

## Tracking

`KV-TLS-OFFLINE-BYPASS` in `cmd/knownviolations_test.go`. GitHub issue: see
`docs/findings/2026-09-19-github-issue-drafts.md`.
