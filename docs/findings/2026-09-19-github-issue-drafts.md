# GitHub issue drafts — read-only-invariant fuzzing campaign (2026-09-19)

Drafted per RULES ("File GitHub issues (don't fix)... Draft them in the
report; I'll OK before filing"). **Not filed.** Awaiting OK.

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
