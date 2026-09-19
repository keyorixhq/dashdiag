# FINDING: `dnf makecache` writes to disk and can trigger a real network fetch — violates both the read-only and no-collector-network invariants

**Date:** 2026-09-19
**Severity:** high
**Status:** reported, not fixed (per fuzzing-campaign policy: report, don't fix)
**Component:** `internal/collectors/packages_linux.go:844-865` (`dnfWarmCache`)

## Summary

`dnfWarmCache` runs `dnf makecache -q` once per process, explicitly to warm
dnf's package metadata cache so later `dnf repolist`/`dnf advisory` calls in
the same `dsd` run hit warm data instead of each independently paying a cold
sync:

```go
var dnfWarmCacheOnce sync.Once

func dnfWarmCache(_ context.Context) {
	dnfWarmCacheOnce.Do(func() {
		warmCtx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
		defer cancel()
		_, _ = runCmd(warmCtx, "dnf", "makecache", pkgFlagQ)
	})
}
```

`dnf makecache` is not a query verb — it downloads and rebuilds dnf's local
repository metadata cache (`/var/cache/dnf/` by default), which is (a) a
real filesystem write outside dsd's own `~/.dsd` state dir and outside any
operator-named `--out`/`--report` path, and (b) if the cache is stale, a
real outbound network fetch of repo metadata. This is a genuine violation of
two of DashDiag's core, explicitly-stated invariants at once:

1. **Read-only**: "dsd... NEVER modifies the system... NEVER makes network
   calls from collectors" (CLAUDE.md, product identity).
2. **No-network-by-default**: every other network-capable path in the repo
   (confirmed exhaustively in the STEP 1 investigation of this campaign)
   funnels through `platform.NetworkAllowed()`/`DSD_OFFLINE`. `dnf
   makecache` bypasses that gate entirely — it's not even recognized as a
   network-capable call site anywhere in the codebase's own policy
   comments, because it's invoked as an ordinary package-manager query.

This is a genuinely more severe finding than the other four in this
campaign — it's not an edge case (unset `$HOME`, an explicit opt-in flag
bypassing a policy) but a call that fires on every `dsd health`/`dsd
security`/CVE-scan run on any rpm/dnf-based host, unconditionally, as part
of the default collector path.

## Evidence

Found by direct code read while building the exec-call allowlist contract
for `FuzzCommandAllowlist` (`cmd/execallowlist_contract_test.go`) — cross-
checking every `dnf` call site against the STEP 1 investigation's summary
(which reported only `repolist`/`advisory` as dnf's observed verbs, missing
`makecache` and `check`). Not caught by the fuzzer itself: `dnfWarmCache`
only runs on an actual rpm/dnf-based Linux host (gated by distro detection),
and neither this session's macOS fuzzing runs nor the Debian-based sandbox
replay test (pve01 CT 230) reach that code path. **This finding is from
code review, not from a live fuzz/sandbox catch** — flagging explicitly
since an rpm-based sandbox run (e.g. on Oracle Linux/OCI, planned as a
follow-up per this session's conversation) would very likely catch it live:
the sandbox oracle ("upper dir contains only contract paths") would show a
write under `/var/cache/dnf/`, and `dnf` is intentionally excluded from the
allowlist's `makecache` shape, so `FuzzCommandAllowlist`'s allowlist oracle
would also fire if a fuzzed/replayed argv ever drove this path on an
rpm-based `dsdfuzzexec` build.

## Impact

Every `dsd health`, `dsd security`, or CVE-related invocation on an rpm/dnf
Linux host (Fedora, RHEL, Rocky, AlmaLinux, openSUSE-with-dnf, etc.)
performs this write+network call once per process, unconditionally — not
opt-in, not flag-gated. On an air-gapped or `DSD_OFFLINE=1` host, this
either fails loudly (acceptable, matches "works offline" if it fails
gracefully) or, worse, silently succeeds using a network path the operator
believed was disabled.

## Suggested fix shape (not applied)

Two independent options, either or both:
1. Gate `dnfWarmCache`'s call behind `platform.NetworkAllowed()` — if
   network is disallowed, skip the warm-cache step entirely and let the
   later `dnf repolist`/`advisory` calls run cold (slower, but correct and
   consistent with every other network-capable path in the repo).
2. Reconsider whether the write-side effect (populating dnf's on-disk
   cache) is acceptable at all for a tool whose entire value proposition is
   "diagnoses without modifying." If dnf's own caching behavior can't be
   short-circuited without writing to disk, this may need to be a
   documented, opt-in-only capability (e.g. behind `--network`, matching
   the existing opt-in network gate) rather than unconditional default
   behavior.

## Tracking

No `KV-*` entry in `cmd/knownviolations_test.go` — unlike this campaign's
other four findings, this one is NOT tolerated by any oracle; it's excluded
from the allowlist contract entirely, so the oracle fails closed (fatal) if
this code path is ever exercised under `FuzzCommandAllowlist`. GitHub
issue: see `docs/findings/2026-09-19-github-issue-drafts.md` (issue #7).
