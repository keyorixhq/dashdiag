# FINDING: `dnf makecache` writes to disk and can trigger a real network fetch — violates the read-only and offline product promises

**Date:** 2026-09-19
**Severity:** Medium (product promise: read-only + offline) — **not a security vulnerability**. No attacker-controlled input reaches this path, no privilege boundary is crossed; the violation is dsd doing something it explicitly promises never to do, not an exploitable weakness. Downgraded from an initial High: all three call paths are flag-gated (`--packages` / `--cve` / `dsd cve --all`, none default-on), and the stall is bounded (not an unbounded hang) end-to-end by each collector's own `Timeout()` — `PackagesCollector` at 50s, `CVEHealthCollector` at 130s — even though `dnfWarmCache`'s own 20s `context.WithTimeout` only bounds the warm-cache step itself, not the follow-up `dnf advisory`/`updateinfo` query calls that inherit whatever budget is left (see the corrected addendum below: a live `--cve` run under a blocked network took the full ~120s, not ~20s). Medium reflects "a real, avoidable promise violation with a bounded, opt-in blast radius," not "silently fires on every run" or "unbounded hang."
**Status:** FIXED (2026-09-20, issue #1103). `dnfWarmCache` and its call sites
have been removed entirely; every remaining `dnf` read-query call site now
leads with `--cacheonly`, so dnf answers only from whatever is already
cached and never refreshes it or touches the network. A cache-miss/failed
`--cacheonly` query now surfaces an explicit "could not check: no cached
dnf metadata" finding rather than a silent clean result. Regression-proofed
by `internal/collectors/dnf_cacheonly_governance_test.go`
(`TestDNFCallSitesUseCacheOnly`), which mechanically asserts via AST that
`dnfWarmCache` no longer exists and every `dnf` call site is
`--cacheonly`-qualified (or the bare `--version` detection probe). The rest
of this document is preserved as the original investigation record.
**Component:** `internal/collectors/packages_linux.go:844-865` (`dnfWarmCache`), reached from three call sites (see Scope below)

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

## Scope — corrected from the initial report

The initial version of this finding characterized `dnfWarmCache` as firing
"on every `dsd health` run, unconditionally." **That was imprecise — all
three call paths are opt-in, flag-gated, not default-on:**

| Call path | Gate | Default state of the gate |
|---|---|---|
| `internal/collectors/packages_linux.go:301` (`collectDNF`, inside `PackagesCollector.Collect`) | `dsd health --packages` | `--packages` defaults to `false` (`cmd/health.go:47`) |
| `internal/collectors/cve_linux.go:692` (`scanAllDNF`, inside `scanAllViaPackageManager` → `ScanAllCVEs`) via `CVEHealthCollector` | `dsd health --cve` | `--cve` defaults to `false` |
| same `ScanAllCVEs` path, via the `dsd cve` subcommand | `dsd cve --all` | opt-in flag on an already-opt-in subcommand |
| `dsd cve <specific-CVE-ID>` (no `--all`) | — | **Does NOT call `dnfWarmCache`** — `CheckCVE` (`cve_linux.go:50`) takes a different path that never warms the cache. |

So this is not "dsd secretly phones home on every run" — it's "an operator
who explicitly asks for a read-only security/package scan (`--packages`,
`--cve`, or `dsd cve --all`) gets an unadvertised write+network side effect
they didn't ask for and `DSD_OFFLINE` doesn't suppress." That's still a real
violation of the "one policy, one gate" invariant every other network path
in the repo respects (an operator who sets `DSD_OFFLINE=1` reasonably
expects it to be a hard kill-switch regardless of which flags they also
pass) — which is why this is rated High despite being opt-in, not a
default-path issue.

## Sweep: is this a pattern, or a one-off?

Per your request, swept every other package-manager refresh/network verb
DashDiag's collectors could plausibly call (`apt-get update`, `zypper
refresh`/`ref`, `yum makecache`, `pacman -Sy*`, `apk update`, `brew update`,
`softwareupdate -l`, `port selfupdate`, `snap refresh`, `flatpak update`,
`fwupdmgr refresh`) across `internal/collectors/*.go` and
`internal/platform/*.go`. **`dnf makecache` is the only real violation.**
Everything else is either genuinely absent from the codebase or already
safe:

| Tool/verb | Verdict |
|---|---|
| `apt-get update` / `apt update` | **Not found.** Only `apt-get -s upgrade` / `--simulate upgrade`/`dist-upgrade` (documented dry-run, no real changes, no metadata refresh) at `packages_linux.go:469,554` and `cve_linux.go:960,966`. |
| `zypper refresh`/`ref` | **Not found.** Only `--version`, `repos`, `needs-rebooting`, `list-patches --category security`, `verify --dry-run`, `locks`, `lp --cve=…`. |
| `yum` (any verb) | **Never exec'd at all** — `"yum"` appears only as a string match categorizing an already-known package-manager name; `detectPackageManager()` never probes it. |
| `pacman -Sy`/`-Syu`/`-Syy` | **Never executed.** `fixPacmanSyu = "pacman -Syu"` (`cve_linux.go:26`) is only used as human-facing remediation-suggestion TEXT in results, never passed to `exec`. |
| `apk update` | **`apk` binary never invoked anywhere in the repo.** |
| `brew update` | **Not found.** Only `brew outdated --quiet` (read-only query) and `which brew` (path lookup). |
| `softwareupdate -l` | **Binary never invoked at all.** |
| `port selfupdate` (MacPorts) | **Not found** — no MacPorts `port` binary invocation exists at all. |
| `snap refresh` | **`snap` binary never invoked** — all `snap`-related matches are filesystem paths/systemd unit names used for detection. |
| `flatpak update` | **Not found.** Only `flatpak list --app` (read-only query). |
| `fwupdmgr refresh` | **Not found.** Only `--version` and `get-upgrades --json` — both consult already-cached metadata per fwupd's own docs, neither forces a refresh. |

`dnf makecache` is a genuine one-off, not a systemic pattern across package
managers — the other package-manager integrations in this codebase were
already written read-only/dry-run from the start.

## Air-gapped hang risk

`dnfWarmCache`'s own 20-second `context.WithTimeout` bounds *that specific
call* — `dnf makecache` itself will be force-killed at 20s (via
`platform.ExecWaitDelay`'s force-kill-after-cancel semantics, same as every
other hardened exec call site), not hang forever. That's a real mitigation
already in place for the warm-cache step. It does NOT, however, bound the
operator-visible total stall: the actual `dnf repolist`/`advisory`/
`updateinfo` query calls that run after it (warm or not) have no timeout of
their own and inherit whatever's left of the *collector's* `Timeout()` — 50s
for `PackagesCollector`, 130s for `CVEHealthCollector`. Measured live (see
the addendum below): a real `dsd health --packages --cve` run under a
blocked network took the full **~120 seconds**, matching bare dnf's own
natural give-up time, not 20s. Still bounded — not an infinite hang — but by
the collector timeouts, not by `dnfWarmCache`'s wrapper.

**Measured live** on pve01 CT 230 (Debian 13 base with `dnf` installed via
apt — a genuine RHEL/Fedora/Rocky host's dnf may tune retries/timeouts
slightly differently, so treat the exact numbers as indicative, not
authoritative, but the SHAPE of the result — bounded-but-long, and
critically, no false-OK — should generalize). Full detail, including
confirmation that dsd reports this honestly rather than as a false-clean
result, is in the addendum at the bottom of this file.

## Draft fix (not applied)

Per your direction, the concrete shape rather than just "gate it":

1. **Remove `dnfWarmCache` and its call sites entirely.** The caching
   optimization it provides (avoiding N cold syncs for N sequential dnf
   queries in one process) doesn't justify an unconditional, ungated write+
   network side effect in a tool whose entire value proposition is
   diagnosing without modifying.
2. **Add `--cacheonly` to the read queries that currently rely on the warm
   cache** (`dnf repolist`, `dnf advisory list/info`, `dnf updateinfo
   list/info` — the actual query call sites already in
   `cmd/execallowlist_contract_test.go`'s `dnf` entry). `--cacheonly` makes
   dnf answer from whatever's already cached, without touching the network
   or writing anything, ever — turning every one of these calls into a
   genuinely read-only query regardless of cache freshness.
3. **Degrade gracefully when the cache is stale/absent**: if `--cacheonly`
   returns empty/stale results (a host that's never run `dnf makecache`
   itself, e.g. a fresh minimal install), the collector should report an
   honest "no cached package metadata available — run `dnf makecache` as
   root to enable this check" finding (matching the codebase's existing
   `needs_root:true`/`*_unreadable:true`/"couldn't measure" disclosure
   pattern), rather than silently returning zero advisories as if the host
   were clean. This is the same false-OK-on-degrade class the project's own
   `bugclass-index.md` already tracks for other collectors — a stale/empty
   cache must not read as "no vulnerabilities found."

4. **Minor**: while verifying this finding live, `Packages.raw.checked`
   stayed `true` even when `status: "query-failed"` — the user-facing
   `status`/`status_reason` fields are correct and honest, but a consumer
   reading only `checked`+`security_updates: 0` (skipping `status`) could
   still misread a failed scan as "checked, found nothing." Worth setting
   `checked: false` (or an equivalent) on the query-failed path in the same
   change, not because it's a live false-OK today, but to remove the latent
   footgun for any future/alternate renderer.

This turns the whole `--packages`/`--cve --all` dnf path into something
that: never writes, never touches the network, and never confuses "we
didn't check" with "we checked and it's fine."

## Tracking

No `KV-*` entry in `cmd/knownviolations_test.go` — unlike this campaign's
other findings, this one was never tolerated by any oracle; `dnf`'s allowlist
entry in `cmd/execallowlist_contract_test.go` had no `makecache` shape, so
`FuzzCommandAllowlist`'s allowlist oracle would have failed closed (fatal) if
that code path were ever exercised live. Red-proofed directly: `TestRedProof_DnfMakecacheFires`
(scratch, not committed) confirmed `checkAllowlist` correctly rejected `dnf
makecache -q`. GitHub issue: see `docs/findings/2026-09-19-github-issue-drafts.md`
(issue #0), filed as issue #1103 and fixed 2026-09-20 (see Status above).

---

## Addendum: air-gapped hang measurement (pve01 CT 230)

Measured on pve01 CT 230 (`dashdiag-sandbox-throwaway`, Debian 13 with `dnf`
4.23.0 installed via apt — the distro itself doesn't matter for this
measurement, only dnf's own network retry/timeout behavior does). A test
repo was pointed at a real, reachable mirror
(`mirror.stream.centos.org/9-stream/BaseOS/x86_64/os/`) to get genuine
network I/O, not an immediately-rejected connection.

**Sanity check (network up)**: `dnf makecache -q` completed in **4.4s**,
fetching 6.8MB of real repodata — confirms this is a genuine network
operation, not a fast no-op.

**"No route to host" (`ip route del default`)**: completed in **0.8s** —
this simulation is NOT representative of a real air-gapped/firewalled host;
the kernel returns `ENETUNREACH` immediately, so it doesn't exercise the
actual risk.

**Silent packet drop (`iptables -A OUTPUT -p tcp --dport 443/80 -j DROP`,
the realistic simulation — an outbound firewall dropping instead of
rejecting, which is how most actual air-gapped/restricted networks
behave)**:
- `timeout 60 dnf makecache -q` — **killed by the 60s cap, still running.**
- `timeout 150 dnf makecache -q` — **dnf gave up on its own at ~120.8s**
  (not the 150s cap), presumably its own internal per-mirror connect-timeout
  × retry-count product.

**Conclusion (revised after the live `dsd` run below)**: bare `dnf
makecache` under a real silent-drop firewall condition hangs for **~120
seconds** before dnf itself gives up. `dnfWarmCache`'s own 20-second
`context.WithTimeout` genuinely bounds *that specific call* — confirmed by
code and consistent with the live run below — but that is NOT the same as
bounding the operator-visible stall for `--packages`/`--cve` to 20s: the
follow-up `dnf advisory`/`updateinfo`/`repolist` query calls that run after
warm-cache (whether it succeeded, failed fast, or was force-killed) are not
independently wrapped, so they inherit whatever's left of the *collector's*
own `Timeout()` — 50s for `PackagesCollector`, 130s for `CVEHealthCollector`
— and can themselves burn most of that budget retrying against the same
unreachable network. See the live measurement immediately below: a real
`dsd health --packages --cve` run under a blocked network took the full
~120s, matching bare dnf's natural give-up time, not the 20s warm-cache
bound alone. Still bounded (not an infinite hang, thanks to the collector
timeouts), still a real UX cost, still a violation of the read-only/offline
promises regardless of how well-bounded the delay is.

## Live verification: does the ~120s stall also produce a false-OK verdict?

The concern this section was written to rule out: does dsd, after a `dnf`
query times out with no cached metadata, silently report "0 advisories /
clean" — a false negative that would be strictly worse than the write+
network side effect itself (an operator trusting a clean security scan that
never actually ran)? **Verified NO — dsd degrades honestly.**

Setup: pve01 CT 230, real dsd binary (cross-compiled, this session's HEAD),
`dnf` detected as the package manager (present via apt, checked before
`apt-get` in `detectPackageManager()`'s probe order so it wins on this
Debian-with-dnf-bolted-on host — the underlying distro doesn't matter, only
that `dnf` resolves). `/var/cache/dnf` cleared, `iptables -A OUTPUT -p tcp
--dport 443/80 -j DROP` (silent drop, not reject), then `dsd health
--packages --cve --json`.

**Baseline (network up, for comparison)**: `CVE` → `status: "OK"`,
`"no pending security advisories — system is up to date"`, `total: 0`.
`Packages` → `status: "INFO"`, `"up to date"`, `checked: true`. (Genuinely
clean per this test repo's actual advisory data, not itself suspicious.)

**Blocked run**: `real 2m0.632s`, dsd exit code **2** (CRIT overall — from
an unrelated `CPU Load/RunQueue` CRIT, itself an artifact of this small
2-vCPU test container's run queue saturating under the concurrent dnf
retry storm, not a dnf/CVE/Packages finding).

```json
{
  "name": "CVE",
  "status": "INFO",
  "inline": "dnf advisory scan timed out — likely a cold metadata cache or slow mirror; retry",
  "duration": "2m0.086306928s",
  "raw": { "package_manager": "dnf", "total": 0, "scan_failed": true,
           "status_reason": "dnf advisory scan timed out — likely a cold metadata cache or slow mirror; retry" }
}
{
  "name": "Packages",
  "status": "INFO",
  "duration": "38.342925201s",
  "raw": { "checked": true, "security_updates": 0, "package_manager": "dnf",
           "status": "query-failed",
           "status_reason": "dnf advisory/updateinfo scan timed out — likely a cold metadata cache or slow mirror; retry" }
}
```

Both checks report `status: "INFO"` (never `"OK"`), both carry an explicit
`scan_failed: true` / `status: "query-failed"` field, and both surface a
human-readable `"...timed out... retry"` message rather than a bare `total:
0`/`security_updates: 0` that could be misread as "checked, found nothing."
This matches the codebase's established honest-degradation pattern
(`needs_root`/`*_unreadable`/"couldn't measure") — **no verdict-integrity
finding, no new `KV-*` entry, no headline change needed.** The one loose
end: `Packages.raw.checked` stays `true` even though the query itself
failed (`status: "query-failed"` is the field that actually carries the
failure) — a minor internal-consistency nit worth a one-line mention in the
draft fix below, not a user-facing false-OK (the `status`/`status_reason`
fields a renderer would actually display are correct).
