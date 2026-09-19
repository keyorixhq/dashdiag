# GitHub issue drafts — read-only-invariant fuzzing campaign (2026-09-19)

Drafted per RULES ("File GitHub issues (don't fix)... Draft them in the
report; I'll OK before filing"). **Not filed.** Awaiting OK.

---

## 0. `dnf makecache` writes to disk and can hit the network, ungated by `DSD_OFFLINE`

**Labels:** bug, medium

**Body:**

`dnfWarmCache` (`internal/collectors/packages_linux.go:844-865`) runs `dnf
makecache -q` once per process on a dnf-based Linux host, explicitly to warm
dnf's metadata cache before later `dnf repolist`/`dnf advisory` calls in the
same run. `dnf makecache` is not a query verb: it writes to dnf's on-disk
metadata cache (`/var/cache/dnf/` by default) and, if that cache is stale,
performs a real outbound network fetch of repo metadata — and does so
regardless of `platform.NetworkAllowed()`/`DSD_OFFLINE`, unlike every other
network-capable path in the repo.

**Scope, corrected from the initial pass**: all three call paths reaching
`dnfWarmCache` are opt-in/flag-gated, not default-on — `dsd health
--packages` (default `false`), `dsd health --cve` (default `false`), and
`dsd cve --all` (opt-in flag on an already-opt-in subcommand); `dsd cve
<specific-CVE-ID>` does not reach it. So this isn't "dsd phones home on
every run" — it's "an operator who explicitly asks for a read-only
security/package scan gets an unadvertised write+network side effect that
`DSD_OFFLINE` doesn't suppress," which still breaks the "one policy, one
gate" invariant every other network path in the repo respects.

**Swept for the same class across every other package manager DashDiag
touches** (apt/apt-get update, zypper refresh/ref, yum makecache, pacman
-Sy*, apk update, brew update, softwareupdate -l, port selfupdate, snap
refresh, flatpak update, fwupdmgr refresh) — `dnf makecache` is the only
real violation; everything else is either never invoked at all, or already
a documented dry-run/read-only query (`apt-get -s upgrade`, `brew
outdated`, `flatpak list`, `fwupdmgr --version`/`get-upgrades`). Not a
systemic pattern, a genuine one-off.

**Air-gapped hang, measured** (pve01 CT 230, real mirror + `iptables ...
DROP` to simulate a silently-firewalled network, not just "no route"): bare
`dnf makecache` took ~120.8s to give up on its own under a silent packet
drop. `dnfWarmCache`'s 20s `context.WithTimeout` genuinely bounds *that
call*, but a live `dsd health --packages --cve` run under the same blocked
network took the full **~120s end-to-end**, not 20s — the follow-up `dnf
advisory`/`updateinfo` query calls aren't independently timed out, so they
inherit whatever's left of each collector's own `Timeout()` (50s for
Packages, 130s for CVE) and burn most of it retrying. Still bounded, not an
unbounded hang, just not bounded to 20s.

**Verified: no false-OK.** The concern that mattered most — does the
~120s timeout ever resolve to a silent "0 advisories, clean" verdict — is
confirmed NOT to happen. The same live run's `CVE` and `Packages` checks
both came back `status: "INFO"` (never `"OK"`) with explicit `scan_failed:
true` / `status: "query-failed"` and a human-readable "...timed out...
retry" message — dsd degrades honestly here, matching its established
disclosure pattern elsewhere. One minor nit found in the process:
`Packages.raw.checked` stays `true` on the failed path even though
`status` correctly says `"query-failed"` — worth fixing alongside the rest
(see draft fix item 4), not itself a live false-OK.

Not caught live by this session's fuzzing (macOS + a Debian sandbox CT
never reach dnf-gated code) — found by code review while building the exec
allowlist contract, and explicitly excluded from it (`dnf`'s allowlist
entry has no `makecache` shape) so the oracle fails closed if a
rpm-based fuzz/sandbox run (planned next, on OCI Oracle Linux) exercises it.

Draft fix: remove `dnfWarmCache` entirely; add `--cacheonly` to the actual
read queries (`repolist`/`advisory`/`updateinfo`) so they answer from
whatever's cached without ever touching the network or disk; when the cache
is empty/stale, report an honest "no cached package metadata — run `dnf
makecache` as root to enable this check" finding rather than silently
returning zero advisories as if the host were clean (the same
false-OK-on-degrade class this project already guards other collectors
against); and set `Packages.raw.checked = false` on the query-failed path
(currently stays `true` even when `status` says `"query-failed"`).

See `docs/findings/2026-09-19-FINDING-dnf-makecache-writes-and-network.md`.

See `docs/findings/2026-09-19-FINDING-dnf-makecache-writes-and-network.md`.

---

## 1. `dsd tls --endpoint` bypasses `DSD_OFFLINE` / `platform.NetworkAllowed()`

**Labels:** bug, medium

**Body:**

`CheckRemoteEndpoint` (`internal/collectors/tls_remote.go`, invoked from
`cmd/tls.go:390` — `dsd tls --endpoint host:port`) dials the given endpoint
unconditionally. It's the only remote-dialing code path in the repo that
doesn't check `platform.NetworkAllowed()` first — every other network call
site (IMDS/cloud-metadata probes, the CVE-enrichment API call, the
`services:` config TCP/HTTP probes, the self-update check) funnels through
that one policy gate, which is off by default and always hard-overridden off
by `DSD_OFFLINE`.

Impact: an operator who sets `DSD_OFFLINE=1` expecting it to be a hard
kill-switch for all outbound dsd traffic still gets a live network
connection if they separately run `dsd tls --endpoint`. `tls` is an
explicit, operator-invoked command, not part of the default `dsd health`
surface, so this isn't a "dsd calls home unexpectedly" bug — it's an
inconsistency in an otherwise-universal safety invariant.

Deterministic regression test proving it (loopback-only, no real external
host contacted): `internal/collectors/tls_remote_offline_test.go::TestTLSEndpointBypassesOfflineGate`.

Suggested fix: add a `platform.NetworkAllowed()` check at the top of
`checkRemoteEndpointLive`, matching every other network call site.

See `docs/findings/2026-09-19-FINDING-tls-endpoint-offline-bypass.md`.

---

## 2. Three `$HOME`-dependent path functions in `internal/baseline` fail open to a CWD-relative path

**Labels:** bug, low

**Body:**

`baselineDir()` (`internal/baseline/baseline.go:67`), `goldenDir()`
(`internal/baseline/golden.go:11`), and `SecurityBaselinePath()`
(`internal/baseline/security_baseline.go:63`) all do:

```go
home, _ := os.UserHomeDir()
return filepath.Join(home, ".dsd", "...")
```

discarding the error. If `$HOME` is unset/unresolvable, this silently
produces a CWD-relative path (`.dsd/baselines`, `.dsd/golden`,
`.dsd/security-baseline.json`) instead of refusing to write — the exact
class of bug `internal/tips/state.go`, `internal/selfupdate/nudge.go`, and
`internal/store/jsonl.go` were deliberately hardened against (same repo,
same `$HOME`-dependent idiom).

Affects `dsd security --save-baseline`, `dsd baseline save`/`diff`, and the
baseline-snapshot path — all opt-in flows, not the default `dsd health`
path.

Deterministic regression test:
`internal/baseline/homefailopen_test.go::TestHomeFailOpen_KnownViolations`.

Suggested fix: mirror `tips/state.go`'s pattern — check the error /
empty-string result and return an explicit "cannot resolve $HOME" error.

See `docs/findings/2026-09-19-FINDING-home-failopen.md`.

---

## 3. `dsd hook install`'s systemd-unit writes aren't `O_NOFOLLOW`-guarded like their siblings

**Labels:** bug, low

**Body:**

`cmd/hook.go:264` and `:269` (writing
`/etc/systemd/system/dsd-health.timer`/`.service` when the systemd-timer
install option is chosen) use plain `os.WriteFile`. Every other write in the
same command (`.bashrc`/`.zshrc`, `scripts/check-health.sh`,
`.git/hooks/pre-push`, `.github/workflows/dsd-health.yml`) goes through this
command's own `O_NOFOLLOW`-guarded write helper.

`os.WriteFile` follows symlinks — a symlink planted at either systemd-unit
path (by a prior install, or an attacker with write access to
`/etc/systemd/system/`) would redirect the write on the next `dsd hook
install` run, a classic TOCTOU/symlink-plant primitive. `dsd hook install`
is the one command family that writes to genuine system paths outside
`~/.dsd`/CWD by design (explicit, interactive, opt-in installer) — the
*feature* is intentional, the hardening gap on these two specific writes is
not.

Suggested fix: route both writes through the same `O_NOFOLLOW`-guarded
helper the rest of `cmd/hook.go` already uses.

See `docs/findings/2026-09-19-FINDING-hook-install-unhardened-systemd-write.md`.

---

## 4. Consolidate the ~10 duplicated hardened-exec call sites behind one shared helper

**Labels:** enhancement

**Body:**

`platform.ResolveTrustedTool` + `platform.HardenedEnv` + `platform.ExecWaitDelay`
+ (now) the `platform.ExecHook` check are applied via the same ~5-line
pattern independently re-typed at ~10 call sites across the repo
(`internal/source/live.go`'s `defaultExec`, `internal/collectors/collector.go`'s
`localeSafeExec`/`localeSafeCmd`, `internal/baseline/since_deploy.go`,
`internal/platform/profile.go`, `internal/init/detector.go`,
`internal/drilldown/drilldown.go`, `internal/inventory/inventory.go`,
`internal/cvedata/rpm.go`, `internal/cvedata/oval_debian.go`) rather than
routed through one shared function. `internal/fleet/fleet.go`'s `ssh`/`scp`
calls are the one documented, deliberate exception (must use the operator's
own `$PATH`/config).

This duplication is why `localeSafeCmd`
(`internal/collectors/collector.go`) was able to silently skip
`ResolveTrustedTool` for its two call sites (`ping`, `route -n get default`
in `network_quick.go`) without anything catching it until this fuzzing
campaign's `platform.ExecHook` wiring surfaced the inconsistency — see the
companion finding
`docs/findings/2026-09-19-FINDING-localesafecmd-path-trust-bypass.md`. A
single shared helper (`platform.RunHardened(ctx, name, args...) (*exec.Cmd,
error)` or similar) would make a future omission structurally harder,
instead of relying on each call site's author remembering the full pattern.

Suggested shape: extend `platform.ResolveTrustedTool` (or a new sibling
function in the same file, since `platform` is contractually stdlib-only and
can't import `internal/source`) to also apply `HardenedEnv`, `ExecWaitDelay`,
and the `ExecHook` check, returning a ready-to-`.Run()`/`.Output()`
`*exec.Cmd`. Each of the ~10 call sites then becomes a one-line call instead
of a ~5-line duplicated block. `internal/collectors/collector.go`'s
`localeSafeExec` additionally wraps output capture into a `source.Result` —
that composition can stay a thin wrapper around the new shared primitive.

See `docs/findings/2026-09-19-FINDING-localesafecmd-path-trust-bypass.md`.

---

## 5. Pre-commit hook's `go test -short -timeout 60s ./...` step is stale — `cmd` package alone now takes ~90s

**Labels:** chore, tooling

**Body:**

`.git/hooks/pre-commit` step 4 runs `go test -short -count=1 -timeout 60s
./...` with a comment noting it was already bumped once ("the cmd package's
test suite alone now regularly takes 30-36s even under -short, so a flat 30s
ceiling here was failing on unrelated commits, not just slow ones"). As of
2026-09-19, measured on a clean checkout with `-short`: the `cmd` package
alone takes **~90s** (89.776s, `-timeout 180s` so it could actually finish
and report a real number instead of being killed at 60s) — well over the
current 60s ceiling.

This is NOT this session's `FuzzCommandAllowlist` fuzz target: it now skips
immediately under `testing.Short()` (0.02s) after this session added that
guard specifically to keep it out of the pre-commit budget. The ~90s is 100%
pre-existing, confirmed two ways: (1) timing a clean `git stash` before any
of this session's changes were applied showed the same order-of-magnitude
duration, and (2) this final re-measurement, with `FuzzCommandAllowlist`
properly skipping, still shows ~90s. Most likely cause:
`cmd/smoke_test.go`'s tests, each of which shells out via `go run
github.com/keyorixhq/dashdiag/cmd/dsd ...` (a full recompile-and-run per
test, not just a process spawn) and does NOT check `testing.Short()` to skip
under `-short` — unlike some `cmd` package tests which already do.

Suggested fix (either, or both):
1. Make `cmd/smoke_test.go`'s slower cases skip under `testing.Short()`
   (matching the pattern `TestHealthPlainExitCode`/`TestHealthJSONValid`/
   `TestNetJSONValid` already use), and/or build the `dsd` binary once instead
   of `go run`-ing it per test case.
2. Raise the pre-commit hook's timeout to match what CI already uses (the
   hook's own comment says CI was bumped 180s→300s for the same reason;
   pre-commit's `-timeout 60s` was apparently never updated to match).

Not filed as a blocker on today's fuzz-harness PR — that commit went in with
an authorized one-time `--no-verify` after manually confirming `go test
-short -timeout 180s ./...` passes clean.

---

## 6. `TestAllExecCallsResolveThroughTrustedWrapper` (and likely other repo-walking governance tests) doesn't skip nested git worktrees

**Labels:** bug, tooling

**Body:**

`internal/collectors/exec_locale_test.go`'s `TestAllExecCallsResolveThroughTrustedWrapper`
walks the module tree from the repo root looking for raw `exec.Command`/
`exec.CommandContext` calls outside `execWrapperFiles`. Its walker
(`exec_locale_test.go:83-92`) already has a `filepath.SkipDir` guard for a
fixed set of directory names (`.scratch`, `.git`, `.claude`, `node_modules`,
`vendor`, `dist`) — but that's an exact-name match, not a dot-prefix or
nested-worktree check. A directory named `.claude-worktrees` (a distinct
sibling name, not nested under `.claude`) doesn't match any entry, so the
walker descends into it. A leftover worktree there (e.g. from a
worktree-isolated subagent run) re-discovers the SAME exec call sites the
outer repo already exempts, now under a different relative path like
`.claude-worktrees/mutation-research/internal/baseline/since_deploy.go:34`
instead of `internal/baseline/since_deploy.go:34`, and fails because the
exemption map (`execWrapperFiles`, keyed by exact relative path) doesn't
match the nested path.

Reproduced 2026-09-19: a genuinely clean, detached-HEAD worktree at
`.claude-worktrees/mutation-research` (matching `origin/main`, no unique
commits) caused this test to fail with 10 false-positive violations, on an
otherwise fully green tree. Removed via `git worktree remove
.claude-worktrees/mutation-research && git worktree prune` as part of this
session — but the underlying test gap remains, and will recur the next time
any tool leaves a worktree directory inside the repo root.

A more robust pattern already exists in this exact codebase:
`write_capable_callsites_test.go`'s walker (`write_capable_callsites_test.go:97-100`)
skips by dot-PREFIX, not exact name — `strings.HasPrefix(info.Name(), ".") ||
info.Name() == "testdata"` — which would catch `.claude-worktrees` (and any
other current or future dot-directory) generically, without needing a
maintained exact-name list. Suggested fix: change
`exec_locale_test.go:88-91`'s `switch d.Name() { case ".scratch", ".git",
".claude", "node_modules", "vendor", "dist": ... }` to a dot-prefix check
(plus keep `node_modules`/`vendor`/`dist` as explicit non-dot entries), or
even more robustly, detect a nested worktree specifically by checking
whether `<dir>/.git` is a regular file (a worktree's `.git` is a file
containing `gitdir: ...`, not a directory — the real repo root's `.git` is
already skipped by name) so a future non-dot-prefixed worktree location
doesn't reopen the same gap. `parsefloat_governance_test.go` is naturally
immune today (it only walks `internal/` and `cmd/`, not the repo root, so a
root-level worktree directory is outside its scan entirely) — but that's a
side effect of its narrower scope, not a deliberate guard, so it's worth
confirming that stays true rather than assuming it.

See the walker in `internal/collectors/exec_locale_test.go` (lines 83-92).
