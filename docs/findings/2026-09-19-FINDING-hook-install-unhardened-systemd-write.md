# FINDING: `dsd hook install`'s systemd unit writes skip the `O_NOFOLLOW` hardening its siblings use

**Date:** 2026-09-19
**Severity:** low
**Status:** reported, not fixed (per fuzzing-campaign policy: report, don't fix)
**Component:** `cmd/hook.go:264,269` (writing
`/etc/systemd/system/dsd-health.timer` and `.service`)

## Summary

`dsd hook install` writes several files as part of its interactive,
explicitly-confirmed installer flow: `.bashrc`/`.zshrc` (append),
`scripts/check-health.sh`, `.git/hooks/pre-push`,
`.github/workflows/dsd-health.yml`, and — when the systemd-timer option is
chosen — `/etc/systemd/system/dsd-health.timer` and
`/etc/systemd/system/dsd-health.service`.

Every one of those writes except the last two goes through this command's
own `O_NOFOLLOW`-guarded write helper (matching the pattern used throughout
the rest of the codebase — `internal/render/writefile.go`,
`cmd/inventory.go`'s `writefile.go`, etc.). The two systemd-unit writes at
`cmd/hook.go:264` and `:269` use plain `os.WriteFile` instead.

## Impact

`os.WriteFile` follows symlinks. If an attacker (or a misconfigured prior
install) can plant a symlink at `/etc/systemd/system/dsd-health.timer` (or
`.service`) pointing at an arbitrary root-owned file, and an operator later
runs `dsd hook install` as root and selects the systemd-timer option, the
write follows the symlink instead of failing — a classic TOCTOU/symlink-plant
primitive. This is the one command family in dsd that writes to genuine
system paths outside `~/.dsd`/CWD by design (an explicit, interactive,
opt-in installer — not a passive diagnostic collector), so the *feature* is
intentional; the hardening gap on these two specific writes is not.

## Evidence

Direct code read (no test written — this is a straightforward audit finding,
not something requiring a fuzz harness to surface):

- `cmd/hook.go:195,215-290`: `.bashrc`/`.zshrc`/`scripts/`/`.git/hooks/`/
  `.github/workflows/` writes all route through the `O_NOFOLLOW`-hardened
  helper.
- `cmd/hook.go:264`: `os.WriteFile(timerPath, ...)` — plain, no `O_NOFOLLOW`.
- `cmd/hook.go:269`: `os.WriteFile(servicePath, ...)` — plain, no `O_NOFOLLOW`.

## Suggested fix shape (not applied)

Route both writes through the same `O_NOFOLLOW`-guarded helper the rest of
`cmd/hook.go` already uses.

## Tracking

No dedicated `KV-*` entry — this finding doesn't affect any of the fuzz
oracles built in this campaign (`dsd hook install` is interactive/confirm-
gated, not part of `FuzzCommandAllowlist`'s driven surface) so there's nothing
for an oracle to tolerate. GitHub issue: see
`docs/findings/2026-09-19-github-issue-drafts.md`.
